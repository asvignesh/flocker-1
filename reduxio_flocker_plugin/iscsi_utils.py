from datetime import datetime
import logging
import os
import re
import shlex
import subprocess
import time

LOG = logging.getLogger(__name__)

class InvalidDataIP(Exception):
    """
    Invalid DatasetIP
    """

def get_initiator_name():
    """Gets the iSCSI initiator name."""
    LOG.info("Running command -> cat /etc/iscsi/initiatorname.iscsi")
    cmd = 'cat /etc/iscsi/initiatorname.iscsi'
    try:
        output = _exec_pipe(cmd)
        lines = output.split('\n')
        for line in lines:
            if '=' in line:
                parts = line.split('=')
                LOG.debug("Returning initiator name {} .".format(parts[1]))
                return parts[1]
    except:
        raise Exception()


def _exec(cmd):
    """Executes a command.

    Runs a command and gets its output.
    :param cmd: The command line to run.
    :returns: The output from the command.
    """
    LOG.info('Running %s', cmd)
    output = subprocess.check_output(shlex.split(cmd))
    if output:
        LOG.debug('Result: %s', output)
    return output


def _do_login_logout(iqn, ip, do_login):
    """Perform the iSCSI login or logout."""
    try:
        action = "-u"
        if do_login:
            action = "-l"
        _exec('iscsiadm -m node %s -T %s -p %s' %
              (action,
               iqn,
               ip))
        LOG.info('Performed %s to %s at %s', action, iqn, ip)
        return True
    except subprocess.CalledProcessError:
        LOG.info('Error logging in.')
    return False


def _exec_pipe(cmd):
    LOG.info('Running %s', cmd)
    sp = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = ''.join(sp.communicate())
    returncode = sp.wait()
    if returncode == 0:
        LOG.debug('Result: %s', output)
        return output
    else:
        LOG.debug(output)
        raise Exception()


def _manage_session(ip_addr, port, do_login=True):
    """Manage iSCSI sessions for all ports in a portal."""
    if ip_addr == '0.0.0.0':
        return
    try:
        output = _exec_pipe('iscsiadm -m discovery -t st -p %s %s' % (ip_addr, port))
    except:
        raise InvalidDataIP("Invalid data ip exception")
    lines = output.split('\n')
    for line in lines:
        if ':' not in line:
            continue
        target = line.split(' ')
        iqn = target[1]
        ip = target[0].split(',')[0]
        _do_login_logout(iqn, ip, do_login)


def iscsi_login(ip_addr, port=3260):
    """Perform an iSCSI login."""
    return _manage_session(ip_addr, port, True)


def iscsi_logout(portal_ip, port=3260):
    """Perform an iSCSI logout."""
    return _manage_session(portal_ip, port, False)


def rescan_iscsi():
    """Perform an iSCSI rescan."""
    start = datetime.now()
    output = _exec('iscsiadm -m session --rescan')
    lines = output.split('\n')
    end = datetime.now()
    LOG.info('Rescan took %s - output: %s', (end - start), lines)


def _get_multipath_device(sd_device):
    """Get the multipath device for a volume.

    Output from multipath -l should be something like:
    36f4032f0004000000000000000000754 dm-2 REDUXIO ,TCAS
        size=16G features='0' hwhandler='0' wp=rw
        |-+- policy='round-robin 0' prio=-1 status=active
        | `- 4:0:0:1 sdc 8:32 active undef running
        |-+- policy='round-robin 0' prio=-1 status=enabled
        | `- 6:0:0:1 sde 8:64 active undef running
        |-+- policy='round-robin 0' prio=-1 status=enabled
        | `- 5:0:0:1 sdd 8:48 active undef running
        `-+- policy='round-robin 0' prio=-1 status=enabled
          `- 3:0:0:1 sdb 8:16 active undef running

    :param sd_device: The SCSI device to look for.
    :return: The /dev/mapper/ multipath device if one exists.
    """
    result = None
    try:
        output = _exec('multipath -l %s' % sd_device)
        if output:
            lines = output.split('\n')
            for line in lines:
                if 'REDUXIO' not in line:
                    continue
                name = line.split(' ')[0]
                result = '/dev/mapper/%s' % name
                LOG.info('Found multipath device %s', result)
                break
    except Exception:
        # Oh well, we tried
        pass

    return result


def find_paths(device_id):
    """Looks for the local device paths.

    Note: The first element will be the multipath device if one is present.

    :param device_id: The page 83 device id.
    :returns: A list of the local paths.
    """
    # TODO: get by /dev/disk/by-uuid
    result = []
    regex = re.compile('sd[a-z]+(?![\d])')
    for dev in os.listdir('/dev/'):
        if regex.match(dev):
            try:
                output = _exec('/lib/udev/scsi_id --page=0x83 '
                               '--whitelisted --device=/dev/%s' %
                               dev)
                device_id_norm = device_id.lower()
                LOG.info("Checking path /dev/{} for device id {} .".format(dev, device_id_norm))
                output_norm = output.decode('utf-8')[1:33].strip().lower()
                LOG.info("Path /dev/{} has device id {} .".format(dev, output_norm))

                LOG.debug(device_id_norm)
                LOG.debug(output_norm)

                if device_id_norm == output_norm:
                    LOG.info('Found device %s at path %s', device_id, dev)
                    result.append('/dev/%s' % dev)
            except Exception:
                LOG.error('Error getting device id for /dev/%s', dev)

    # Functional tests always want the same device reported
    result.sort()

    if result:
        # Check if there is a multipath device
        mpath_dev = _get_multipath_device(result[0])
        if mpath_dev:
            result.insert(0, mpath_dev)
    return result


def remove_device(path):
    """Prepare removal of SCSI device.

    :param path: The /dev/sdX or /dev/mapper/X path to remove.
    """
    if not path:
        return

    if '/dev/sd' in path:
        LOG.info("Trying to remove device from path {} .".format(path))
        sd = path.replace('/dev/', '')
        remove_path = '/sys/block/%s/device/delete' % sd
        if os.path.exists(remove_path):
            try:
                _exec('blockdev --flushbufs %s' % path)
                time.sleep(4)
            except Exception:
                LOG.exception('Error flushing IO to %s', path)
            try:
                _exec('sh -c "echo 1 > %s"' % remove_path)
                time.sleep(1)
            except Exception:
                LOG.exception('Error removing device %s', sd)
    else:
        LOG.info("Trying to remove device from multipath {} .".format(path))
        try:
            path = path.replace('/dev/mapper/', '')
            _exec('multipath -f %s' % path)
        except Exception:
            LOG.exception('Error removing multipath device %s', path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # Get command line arguments
