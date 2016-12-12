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

logger = logging.getLogger(__name__)


class ISCSIDiscoveryFailure(Exception):
    """
    Invalid DatapathIP
    """


class ISCSILoginFailed(Exception):
    """
    Invalid DatapathIP
    """


def get_initiator_name():
    """Gets the iSCSI initiator name."""
    logger.debug('Getting the initiator name.')
    cmd = 'cat /etc/iscsi/initiatorname.iscsi'
    try:
        output = _exec_pipe(cmd=cmd)
        lines = output.split('\n')
        for line in lines:
            if '=' in line:
                parts = line.split('=')
                logger.debug("Returning initiator name {} .".format(parts[1]))
                return parts[1]
    except:
        logger.error('Initiator name could not be found!')
        raise Exception('Unable to find initiator name')


def _exec(cmd):
    """Executes a command.

    Runs a command and gets its output.
    :param cmd: The command line to run.
    :returns: The output from the command.
    """
    logger.debug('Running command -> {}'.format(cmd))
    output = subprocess.check_output(shlex.split(cmd))
    if output:
        logger.debug('Result: {}'.format(output))
    return output


def is_multipath_tools_installed():
    try:
        _exec('multipath')
    except:
        raise Exception('multipath command error')


def _exec_pipe(cmd, log_command=True):
    if log_command:
        logger.debug('Running command -> {}'.format(cmd))
    sp = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = ''.join(sp.communicate())
    returncode = sp.wait()
    if returncode == 0:
        logger.debug('Result: {}'.format(output))
        return output
    else:
        logger.error(output)
        raise Exception('Command returned with non-zero return code')


def _do_login_logout(iqn, ip, do_login):
    """Perform the iSCSI login or logout."""
    try:
        start = datetime.now()
        action = "-u"  # for log out
        if do_login:
            logger.info('Trying to perform iSCSI login with iqn {}, ip {} .'.format(iqn, ip))
            action = "-l"
        else:
            logger.info('Trying to perform iSCSI logout with iqn {}, ip {} .'.format(iqn, ip))
        _exec('iscsiadm -m node {} -T {} -p {}'.format(action, iqn, ip))
        end = datetime.now()
        if do_login:
            logger.debug('Performed login with {} at {}, it took {}'.format(action, iqn, ip, (end - start)))
        return True
    except Exception as e:
        logger.error(str(e))
    return False


def enable_chap(iqn, ip, chap_user, chap_password):
    update_props = 'iscsiadm -m node -T {} -p {} --op=update '.format(iqn, ip)
    set_chap_auth = update_props + '--name node.session.auth.authmethod --value=CHAP'
    set_chap_user = update_props + '--name node.session.auth.username --value={}'.format(chap_user)
    set_chap_password = update_props + '--name node.session.auth.password --value={}'.format(chap_password)
    try:
        logger.info('Trying to add chap information, chap username: {} and chap password'.format(chap_user))
        _exec_pipe(cmd=set_chap_auth)
        _exec_pipe(cmd=set_chap_user)
        _exec_pipe(cmd=set_chap_password, log_command=False)
        logger.info('Successfully configured chap information for the login,'
                    ' iqn: {}, ip {}, chap username: {}'.format(iqn, ip, chap_user))
    except Exception as e:
        logger.error("unable to set chap configuration, error: {}".format(str(e)))
        raise Exception(str(e))


def _manage_session(ip_addr, port, chap_user, chap_password, do_login=True):
    """Manage iSCSI sessions for all ports in a portal."""
    logger.info('Managing session for portal ip address {}, port {}, do_login {}'.format(ip_addr, port, do_login))
    if ip_addr == '0.0.0.0':
        logger.debug('Return, since ip is {} .'.format(ip_addr))
        return
    try:
        output = _exec_pipe(cmd='iscsiadm -m discovery -t st -p {} {}'.format(ip_addr, port))
    except Exception as e:
        logger.error(str(e))
        raise ISCSIDiscoveryFailure("Failed to discover targets")
    lines = output.split('\n')
    login_success = False
    for line in lines:
        if ':' not in line:
            continue
        target = line.split(' ')
        iqn = target[1]
        ip = target[0].split(',')[0]
        logger.debug('Getting iqn {}, ip {}, from line {} .'.format(iqn, ip, line))
        if chap_user and chap_password:
            enable_chap(iqn, ip, chap_user, chap_password)
        _do_login_logout(iqn, ip, not do_login)
        login_success |= _do_login_logout(iqn, ip, do_login)
    if not login_success:
        raise ISCSILoginFailed("Failed to login to iscsi targets")


def iscsi_session_login(ip_addr, port=3260):
    """Perform an iSCSI login."""
    logger.info('Trying to do iscsi session logging with ip {} and port {} .'.format(ip_addr, port))
    return _manage_session(ip_addr, port, True)


def iscsi_session_logout(portal_ip, port=3260):
    """Perform an iSCSI logout."""
    logger.info('Trying to do iscsi session logout with portal ip {} and port {} .'.format(portal_ip, port))
    return _manage_session(portal_ip, port, False)


def rescan_iscsi_session():
    """Perform an iSCSI rescan."""
    logger.info("Rescanning scsi bus for attached disk")
    start = datetime.now()
    output = _exec('iscsiadm -m session --rescan')
    lines = output.split('\n')
    end = datetime.now()
    logger.debug('Rescan took {} - output: {}'.format((end - start), lines))


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
    logger.info('Checking for multipath with path {} .'.format(sd_device))
    result = None
    try:
        output = _exec('multipath -l {}'.format(sd_device))
        if output:
            lines = output.split('\n')
            for line in lines:
                if 'REDUXIO' not in line:
                    continue
                name = line.split(' ')[0]
                result = '/dev/mapper/{}'.format(name)
                logger.debug('Found multipath device {}'.format(result))
                break
    except Exception:
        logger.error('No multipath with path {} .'.format(sd_device))
        # Oh well, we tried.. simply pass it and go with the disk instead of mapper
        pass

    return result


def find_paths(device_id):
    """Looks for the local device paths.

    Note: The first element will be the multipath device if one is present.

    :param device_id: The page 83 device id.
    :returns: A list of the local paths.
    """
    logger.info("Finding paths with device id {} .".format(device_id))
    result = []
    regex = re.compile('sd[a-z]+(?![\d])')
    for dev in os.listdir('/dev/'):
        if regex.match(dev):
            logger.debug('Checking device id of path /dev/{} .'.format(dev))
            try:
                output = _exec('/lib/udev/scsi_id --page=0x83 '
                               '--whitelisted --device=/dev/{}'.format(dev))
                device_id_norm = device_id.lower()
                logger.debug("Checking path /dev/{} for device id {} .".format(dev, device_id_norm))
                output_norm = output.decode('utf-8')[1:33].strip().lower()
                logger.debug("Path /dev/{} has device id {} .".format(dev, output_norm))

                logger.debug(device_id_norm)
                logger.debug(output_norm)

                if device_id_norm == output_norm:
                    logger.info('Found device {} at path {}'.format(device_id, dev))
                    result.append('/dev/{}'.format(dev))
            except Exception:
                logger.error('Error getting device id for /dev/{}'.format(dev))

    # ClusterHQ Functional tests always want the same device reported
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
    logger.debug("Trying to remove device from path {} .".format(path))
    if not path:
        return

    if '/dev/sd' in path:
        sd = path.replace('/dev/', '')
        remove_path = '/sys/block/{}/device/delete'.format(sd)
        if os.path.exists(remove_path):
            try:
                _exec('blockdev --flushbufs {}'.format(path))
                time.sleep(4)
            except Exception:
                logger.error('Error flushing IO to {}'.format(path))
            try:
                _exec('sh -c "echo 1 > {}"'.format(remove_path))
                time.sleep(1)
            except Exception:
                logger.error('Error removing device {}'.format(sd))
    else:
        logger.debug("Trying to remove device from multipath {} .".format(path))
        try:
            path = path.replace('/dev/mapper/', '')
            _exec('multipath -f {}'.format(path))
        except Exception:
            logger.error('Error removing multipath device {}'.format(path))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
