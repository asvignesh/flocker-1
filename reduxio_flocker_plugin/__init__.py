'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
from flocker.node import BackendDescription, DeployerType

from reduxio_flocker_plugin.reduxio_storagedriver import reduxio_init_from_configuration
from iscsi_utils import get_initiator_name, _exec
import logging
from logging.handlers import RotatingFileHandler

LOG_FILENAME = '/var/log/reduxio.log'

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

handler = logging.handlers.RotatingFileHandler(LOG_FILENAME,
                                               maxBytes=5 * 1024 * 1024,
                                               backupCount=3)
handler.setFormatter(logging.Formatter('%(asctime)s - %(module)s - %(levelname)s - %(funcName)s: %(message)s'))

logger.addHandler(handler)


def api_factory(cluster_id, **kwargs):
    try:
        if kwargs[u'rdx_ip']:
            rdx_ip = kwargs[u'rdx_ip']
        else:
            logger.error('Agent.yml is not configured properly.')
            raise Exception('Agent.yml is not configured properly.')

        if kwargs[u'password']:
            rdx_password = kwargs[u'password']
        else:
            logger.error('Agent.yml is not configured properly.')
            raise Exception('Agent.yml is not configured properly.')
    except Exception as e:
        logger.error('Agent.yml is not configured properly.')
        raise Exception()
    return reduxio_init_from_configuration(cluster_id=cluster_id,
                                           rdx_ip=rdx_ip,
                                           password=rdx_password)


try:
    get_initiator_name()
except:
    logger.error('Unable to get initiator-name, please make sure that open-iscsi is installed.')
    raise Exception()

try:
    _exec('multipath')
except:
    logger.error('Error running multipath, please make sure that multipath-tools are installed.')
    raise Exception()

FLOCKER_BACKEND = BackendDescription(
    name=u"reduxio_flocker_plugin",
    needs_reactor=False, needs_cluster_id=True,
    api_factory=api_factory, deployer_type=DeployerType.block)
