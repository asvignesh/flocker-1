'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.

simple helper utility to generate the volume name and host name, will use for profiles later
'''
import random
import socket
import string
import logging
import time
import os
import shutil
import gzip

__author__ = 'vignesh'
VOLUME_MAX_LEN = 18
HOST_MAX_LEN = 9
logger = logging.getLogger(__name__)


class RdxHelper(object):
    @staticmethod
    def _volume_name_from_id(dataset_id):
        logger.debug('Generating Volume name from dataset id {} ...'.format(dataset_id))
        vol_name = 'Fl-' + dataset_id[:VOLUME_MAX_LEN] + ''.join(
            random.sample(string.ascii_lowercase, HOST_MAX_LEN))
        logger.debug('Generated Volume name is {} .'.format(vol_name))
        return vol_name

    @staticmethod
    def _host_name():
        logger.debug('Generating hostname...')
        host_name = 'FN-' + socket.gethostbyname(socket.getfqdn()) + '-' + ''.join(
            random.sample(string.ascii_lowercase, HOST_MAX_LEN))
        host_name = host_name.replace('.', '_')
        logger.debug('Generated hostname is {} .'.format(host_name))
        return host_name


class Validations(object):
    def _is_chap_credentials_configured_and_valid(self, args):
        if len(args[u'chap_user']) > 255:
            logger.error("Error in agent.yml, chap username length must not exceed 255.")
            raise Exception("Configured chap username exceeds the limit.")
        if len(args[u'chap_password']) < 12 or len(args[u'chap_password']) > 16:
            logger.error("Error in agent.yml, chap password must be between 12-16 number of characters.")
            raise Exception("Configured chap password is of invalid length.")
        return True

    def _is_chap_enabled(self, args):
        if u'chap_user' in args and u'chap_password' not in args and args[u'chap_user']:
            logger.error("Error in agent.yml, chap username is configured without chap password.")
            raise Exception("Chap username configured without chap password.")
        if u'chap_user' not in args and u'chap_password' in args and args[u'chap_password']:
            logger.error("Error in agent.yml, chap password configured without chap username.")
            raise Exception("Chap password configured without chap username.")
        if u'chap_user' in args and u'chap_password' in args:
            return self._is_chap_credentials_configured_and_valid(args)
        return False

    def _is_rdx_config_valid(self, args):
        if u'rdx_ip' not in args or u'password' not in args:
            logger.error("Error in agent.yml, both Reduxio ip/dns and password must be configured.")
            raise Exception("Both Reduxio ip/dns and password must be configured in agent.yml.")
        if not args[u'rdx_ip']:
            logger.error("Error in agent.yml, configured Reduxio ip/dns must not be empty.")
            raise Exception("Configured Reduxio ip/dns must not be empty.")
        if not args[u'password']:
            logger.error("Error in agent.yml, configured Reduxio storage password must not be empty.")
            raise Exception("Configured Reduxio storage password must not be null.")


class ReduxioLogTimeFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = self.converter(record.created)
        t = time.time()
        sec = 0
        tz = '+'
        if time.localtime(t).tm_isdst and time.daylight:
            sec = -time.altzone
        else:
            sec = -time.timezone
        if sec < 0:
            tz = '-'
            sec *= -1
        hr = sec / 60 / 60
        hr = "{0:0=2d}".format(hr)
        min = (sec / 60) % 60
        min = "{0:0=2d}".format(min)
        tz = tz + hr + min
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime("%Y-%m-%d %H:%M:%S", ct)
            s = "%s.%06d %s" % (t, record.msecs, tz)
        return s


class RotatingFileHandlerWithCompress(logging.handlers.RotatingFileHandler):
    def doRollover(self):

        if self.stream:
            self.stream.close()
            self.stream = None
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = "{}.{}.gz".format(self.baseFilename, i)
                dfn = "{}.{}.gz".format(self.baseFilename, i + 1)
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            dfn = self.baseFilename + ".1.gz"
            if os.path.exists(dfn):
                os.remove(dfn)
            with open(self.baseFilename, 'rb') as f_in, gzip.open(dfn, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(self.baseFilename)
        if not self.delay:
            self.stream = self._open()
