'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
from flocker.node import BackendDescription, DeployerType

from reduxio_storkit_flocker.reduxio_storagedriver import reduxio_init_from_configuration
from iscsi_utils import get_initiator_name, is_multipath_tools_installed
import logging
import time
import os
import shutil
import gzip

LOG_FILENAME = '/var/log/reduxio_storkit_flocker.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class DifferentFormatter(logging.Formatter):
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
                sfn = "%s.%d.gz" % (self.baseFilename, i)
                dfn = "%s.%d.gz" % (self.baseFilename, i + 1)
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


handler = RotatingFileHandlerWithCompress(LOG_FILENAME,
                                          maxBytes=5 * 1024 * 1024,
                                          backupCount=10)
handler.setFormatter(DifferentFormatter('%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s'))

logger.addHandler(handler)


def api_factory(cluster_id, **kwargs):
    try:
        if u'rdx_ip' not in kwargs or u'password' not in kwargs:
            logger.error('Both reduxio ip and password must be configured.')
            raise Exception()

        if not kwargs[u'rdx_ip'] or not kwargs[u'password']:
            logger.error('Reduxio ip and password can not be empty.')
            raise Exception()

        rdx_ip = kwargs[u'rdx_ip']
        rdx_password = kwargs[u'password']

        chap_password = None
        chap_user = None

        if u'chap_user' in kwargs and u'chap_password' in kwargs:
            if kwargs[u'chap_user'] and kwargs[u'chap_password']:
                chap_user = kwargs[u'chap_user']
                chap_password = kwargs[u'chap_password']
                if len(chap_user) > 255:
                    logger.error('chap username is too large, must be of length between 1 and 255.')
                    raise Exception()
                if len(chap_password) < 12 or len(chap_password) > 16:
                    logger.error('chap password is either too small or too long, must be of length between 12 and 16.')
                    raise Exception()
            elif kwargs[u'chap_user'] and not kwargs[u'chap_password']:
                logger.error('chap password cannot be empty.')
                raise Exception()
            elif kwargs[u'chap_password'] and not kwargs[u'chap_user']:
                logger.error('chap username cannot be empty.')
                raise Exception()
        elif u'chap_user' in kwargs and u'chap_password' not in kwargs:
            logger.error('chap username is defined without chap password.')
            raise Exception()
        elif u'chap_user' not in kwargs and u'chap_password' in kwargs:
            logger.error('chap password is defined without chap username.')
            raise Exception()

    except Exception as e:
        logger.error('Agent.yml is not configured properly.')
        raise Exception('Agent.yml is not configured properly.')
    return reduxio_init_from_configuration(cluster_id=cluster_id,
                                           rdx_ip=rdx_ip,
                                           password=rdx_password,
                                           chap_user=chap_user,
                                           chap_password=chap_password)


try:
    get_initiator_name()
except:
    logger.error('Unable to get initiator-name, please ensure the relevant package is installed.')
    raise Exception('Unable to get initiator-name.')

try:
    is_multipath_tools_installed()
except:
    logger.error('Error running multipath, please ensure the relevant package is installed.')
    raise Exception('Error running multipath.')

FLOCKER_BACKEND = BackendDescription(
    name=u"reduxio_storkit_flocker",
    needs_reactor=False, needs_cluster_id=True,
    api_factory=api_factory, deployer_type=DeployerType.block)
