'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.

simple helper utility to generate the volume name and host name, will use for profiles later
'''
import random
import socket
import string
import logging

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
