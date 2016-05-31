import random
import socket
import string

__author__ = 'vignesh'
VOLUME_MAX_LEN = 18
HOST_MAX_LEN = 9


class RdxHelper(object):
    @staticmethod
    def _volume_name_from_id(dataset_id):
        return 'Fl-' + dataset_id[:VOLUME_MAX_LEN] + ''.join(
            random.sample(string.ascii_lowercase, HOST_MAX_LEN))

    @staticmethod
    def _host_name():
        host_name = 'FN-' + socket.gethostbyname(socket.getfqdn()) + '-' + ''.join(
            random.sample(string.ascii_lowercase, HOST_MAX_LEN))
        host_name = host_name.replace('.', '_')
        return host_name
