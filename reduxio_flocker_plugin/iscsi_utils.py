'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.

ISCSI Utility functions for iscsi tools and multi path commands
'''
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
        raise Exception('Unable to find initiator name')


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
        raise Exception('Command returned with non-zero return code')


def _do_login_logout(iqn, ip, do_login):
    """Perform the iSCSI login or logout."""
    try:
        action = "-u"  # for log out
        if do_login:
            logging.debug('Trying to perform iSCSI login.')
            action = "-l"
        else:
            logging.debug('Trying to perform iSCSI logout.')
        _exec('iscsiadm -m node %s -T %s -p %s' %
              (action,
               iqn,
               ip))
        LOG.info('Performed %s to %s at %s', action, iqn, ip)
        return True
    except subprocess.CalledProcessError:
        if do_login:
            LOG.info('Error while performing iSCSI login.')
        else:
            LOG.info('Error while performing iSCSI logout.')
    return False


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


def iscsi_session_login(ip_addr, port=3260):
    """Perform an iSCSI login."""
    logging.debug('Trying to do iscsi session logging with ip {} and port 3260 .'.format(ip_addr))
    return _manage_session(ip_addr, port, True)


def iscsi_session_logout(portal_ip, port=3260):
    """Perform an iSCSI logout."""
    logging.debug('Trying to do iscsi session logout with portal ip {} and port 3260 .'.format(portal_ip))
    return _manage_session(portal_ip, port, False)


def rescan_iscsi_session():
    """Perform an iSCSI rescan."""
    logging.info('Trying to perform iscsi session rescan.')
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
        logging.info('Checking for multipath with path {} .'.format(sd_device))
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
        logging.info('No multipath with path {} .'.format(sd_device))
        # Oh well, we tried.. simply pass it and go with the disk instead of mapper
        pass

    return result


def find_paths(device_id):
    """Looks for the local device paths.

    Note: The first element will be the multipath device if one is present.

    :param device_id: The page 83 device id.
    :returns: A list of the local paths.
    """
    result = []
    regex = re.compile('sd[a-z]+(?![\d])')
    for dev in os.listdir('/dev/'):
        if regex.match(dev):
            LOG.info('Checking device id of path /dev/{} .'.format(dev))
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

    # ClusterHQ Functional tests always want the same device reported
    result.sort()

    if result:
        # Check if there is a multipath device
        logging.info('Checking for a multipath')
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
