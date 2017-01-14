'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
from flocker.node import BackendDescription, DeployerType

from reduxio_storkit_flocker.reduxio_storagedriver import reduxio_init_from_configuration
from iscsi_utils import get_initiator_name, is_multipath_tools_installed, is_iscsiadm_installed
from rdx_helper import Validations, RotatingFileHandlerWithCompress, ReduxioLogTimeFormatter
import logging

LOG_FILENAME = '/var/log/reduxio_storkit_flocker.log'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


handler = RotatingFileHandlerWithCompress(LOG_FILENAME,
                                          maxBytes=5 * 1024 * 1024,
                                          backupCount=10)
handler.setFormatter(ReduxioLogTimeFormatter('%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s'))

logger.addHandler(handler)


def api_factory(cluster_id, **kwargs):
    Validations()._is_rdx_config_valid(args=kwargs)
    rdx_ip = kwargs[u'rdx_ip']
    rdx_password = kwargs[u'password']

    chap_password = None
    chap_user = None
    if Validations()._is_chap_enabled(args=kwargs):
        chap_user = kwargs[u'chap_user']
        chap_password = kwargs[u'chap_password']
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

try:
    is_iscsiadm_installed()
except:
    logger.error('Error running iscsiadm command, please ensure the relevant package is installed.')
    raise Exception('Error running iscsiadm command.')

FLOCKER_BACKEND = BackendDescription(
    name=u"reduxio_storkit_flocker",
    needs_reactor=False, needs_cluster_id=True,
    api_factory=api_factory, deployer_type=DeployerType.block)
