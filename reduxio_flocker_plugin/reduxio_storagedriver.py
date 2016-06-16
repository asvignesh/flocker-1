'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
import logging
import time
import uuid

from bitmath import Byte, GiB
from flocker.node.agents.blockdevice import (
    VolumeException, AlreadyAttachedVolume, IProfiledBlockDeviceAPI,
    UnknownVolume, UnattachedVolume,
    IBlockDeviceAPI, BlockDeviceVolume
)
from twisted.python import filepath
from twisted.python.constants import Values
from zope.interface import implementer

from iscsi_utils import get_initiator_name, _manage_session, rescan_iscsi_session, find_paths, remove_device
from rdx_cli_api import ReduxioAPI
from rdx_helper import RdxHelper

__author__ = 'vignesh'

MAX_RESCAN_ATTEMPTS = 4
SLEEP_BWN_RESCAN_IN_S = 5
logger = logging.getLogger(__name__)


# logging.basicConfig(filename=LOG_FILENAME,
#                     level=logging.DEBUG,
#                     format='%(asctime)s - %(module)s - %(levelname)s - %(funcName)s: %(message)s')


class VolumeShrinkFailure(Exception):
    """
    Failed to shrink volume, resize to lesser value
    """


class VolumeAttached(VolumeException):
    """
    Attempting to destroy an attached volume
    """


class VolumeCreationFailure(Exception):
    """
    Volume creation failed
    """


class VolumeDestroyFailure(Exception):
    """
    destroy volume failed
    """


class VolumeAttachFailure(Exception):
    """
    attach volume failed
    """


class VolumeDetachFailure(Exception):
    """
    detach volume failed
    """


class ListVolumesFailure(Exception):
    """
    list volumes failed
    """


class GetDevicePathFailure(Exception):
    """
    get_device_path failed
    """


class VolumeProfiles(Values):
    """
    :ivar GOLD: The profile for Critical Apps.
    :ivar SILVER: The profile for Normal apps/default storage.
    :ivar BRONZE: The profile for archival apps .
    :ivar DEFAULT: The default profile if none is specified.
    """
    GOLD = 'gold'
    SILVER = 'silver'
    BRONZE = 'bronze'
    DEFAULT = SILVER


@implementer(IBlockDeviceAPI)
@implementer(IProfiledBlockDeviceAPI)
class ReduxioStorageDriverAPI(object):
    def __init__(self, cluster_id, rdx_ip, password):
        logger.info("ReduxioStorageDriverAPI Initializing")

        self._cluster_id = cluster_id
        self._rdx_ip = rdx_ip
        self._password = password

        logging.debug("Initializing {}; {};".format(self._cluster_id, self._rdx_ip))

        self._rdxapi = ReduxioAPI(host=rdx_ip, user="rdxadmin", password=password)
        self._rdxhelper = RdxHelper()

        self.initiator_name = get_initiator_name()
        logging.debug("Initiator name is {} .".format(self.initiator_name))

    def compute_instance_id(self):
        """
        :return: the iSCSI Initiator IQN Name
        Sample : iqn.2016-04.com.ubuntu.iscsi:nss3499

        This will be compared against ``BlockDeviceVolume.attached_to``
        to determine which volumes are locally attached and it will be used
        with ``attach_volume`` to locally attach volumes.

        """
        return unicode(self.initiator_name)

    # def allocation_unit(self):
    #     """
    #     Return allocation unit
    #     """
    #     logging.debug("vSphere allocation unit: " +
    #                   str(int(GiB(4).to_Byte().value)))
    #     return int(GiB(4).to_Byte().value)

    def _normalize_uuid(self, uuid):
        uuid = uuid.translate(None, " -\n'")
        uuid = uuid.lower()
        return uuid

    def create_volume_with_profile(self, dataset_id, size, profile_name):
        """
        :param dataset_id: UUID generate by FLocker
        :param size: size of disk in bytes
        :param profile_name: GOLD / SILVER/ BRONZE
        :return: BlockDeviceVolume struct
        """
        try:
            logging.debug("###########################")
            volume_name = self._rdxhelper._volume_name_from_id(str(dataset_id))
            logger.info(
                "Trying to create volume named {} of size {}GB.".format(volume_name, Byte(size).to_GiB().__long__()))
            self._rdxapi.create_volume(name=volume_name, size=Byte(size).to_GiB().__long__(),
                                       description=str(dataset_id), blocksize=512)
            logger.info("Checking if the volume {} is created.".format(volume_name))
            blockdevice_id = self._rdxapi.find_volume_by_name(name=volume_name)[u'wwid']
            logging.debug("Volume created successfully")
            logging.debug(blockdevice_id)
        except Exception as e:
            logging.error("Cannot create volume because of exception : " + str(e))
            raise VolumeCreationFailure(e)
        volume = self.build_block_device(blockdevice_id=blockdevice_id, dataset_id=dataset_id, volume_size=size)
        logging.debug("vSphere Block Device Volume ID {}".format(volume.blockdevice_id))
        return volume

    def build_block_device(self, blockdevice_id, dataset_id, volume_size, attach_to=None):
        return BlockDeviceVolume(
            size=volume_size,
            dataset_id=dataset_id,
            attached_to=attach_to,
            blockdevice_id=unicode(blockdevice_id))

    # def build_block_device_struct(self, blockdevice_id, dataset_id, size):
    #     return BlockDeviceVolume(
    #         size=size,
    #         dataset_id=dataset_id,
    #         blockdevice_id=unicode(blockdevice_id))

    def create_volume(self, dataset_id, size):
        """
        Create a new volume on the array.
        :param dataset_id: UUID generate by FLocker
        :param size: size of disk in bytes
        :return: BlockDeviceVolume struct
        """
        try:
            volume_name = self._rdxhelper._volume_name_from_id(str(dataset_id))
            logger.info(
                "Trying to create volume named {} of size {} GB.".format(volume_name, Byte(size).to_GiB().__long__()))
            self._rdxapi.create_volume(name=volume_name, size=Byte(size).to_GiB().__long__(),
                                       description=str(dataset_id), blocksize=512)
            logger.info("Checking if the volume {} is created.".format(volume_name))
            blockdevice_id = self._rdxapi.find_volume_by_name(name=volume_name)[u'wwid']
            logging.debug("Volume created successfully")
            logging.debug(blockdevice_id)
        except Exception as e:
            logging.error("Cannot create volume because of exception : " + str(e))
            raise VolumeCreationFailure(e)
        volume = self.build_block_device(blockdevice_id=blockdevice_id, dataset_id=dataset_id, volume_size=size)
        logging.debug("Block Device Volume ID {}".format(volume.blockdevice_id))
        return volume

    def destroy_volume(self, blockdevice_id):
        """
        Destroy an existing volume.

        :param blockdevice_id: WWID in the reduxio
        :return: None
        """
        try:
            volume_info = self.find_volume_by_blockdevice_id(blockdevice_id)
            volume_name = volume_info[u'name']
        except Exception as e:
            logging.error("Unable to find the volume with the provided blockdevice_id " + str(e))
            raise UnknownVolume(e)

        try:
            logger.info("Checking if the volume {} is attached to any node/s.".format(volume_name))
            assignment_list = self._rdxapi.list_assignments(vol_name=volume_name)
            if (len(assignment_list) > 0):
                logging.error("Volume {} is attached to a node, so it cannot be destroyed.".format(volume_name))
                raise VolumeAttached(blockdevice_id)

            # volume_name = self._rdxhelper._volume_name_from_id(str(dataset_id))
            logger.info("Trying to delete the volume {} .".format(volume_name))
            self._rdxapi.delete_volume(name=volume_name)
        except Exception as e:
            logging.error("Destroy volume failed due to error " + str(e))
            raise VolumeDestroyFailure(e)

    def attach_volume(self, blockdevice_id, attach_to):
        """
        Attach an existing volume to an initiator.

        If host is not created, it will create the host
        :param blockdevice_id: WWID of the reduxio Volume
        :param attach_to: is the value generated by the compute_instance_id ... here IQN of the current node
        :return: BlockDeviceVolume with attachd_to
        """

        logging.debug("Attaching {} to {}".format(blockdevice_id,
                                                  attach_to))
        try:
            volume_info = self.find_volume_by_blockdevice_id(blockdevice_id)
            dataset_id = uuid.UUID(volume_info[u'description'])
            volume_name = volume_info[u'name']
        except Exception as e:
            logging.error('An error occurred finding the  volume {} : {}'.format(blockdevice_id, e))
            raise UnknownVolume(e)

        try:
            logger.info("Checking if the volume {} is attached to any node/s".format(volume_name))
            assignmentlist = self._rdxapi.list_assignments(vol_name=volume_name)
            if (len(assignmentlist) > 0):
                logging.error("Volume {} is already attached to a node.".format(volume_name))
                raise AlreadyAttachedVolume(blockdevice_id)

            hostname = None
            host_list = self._rdxapi.list_hosts()
            logger.info("Checking if the host with iscsi name {} already exist.".format(attach_to))
            for host in host_list:
                if (attach_to == host[u'iscsi_name']):
                    hostname = host[u'name']
                    break

            if (hostname is None):
                hostname = self._rdxhelper._host_name()
                logger.info(
                    "Trying to create host {} with iscsi name {} since it does not exist.".format(hostname, attach_to))
                self._rdxapi.create_host(name=hostname, iscsi_name=attach_to)

            logger.info("Trying to assign host {} to volume {} .".format(hostname, volume_name))
            self._rdxapi.assign(vol_name=volume_name, host_name=hostname)
            volume_size = volume_info[u'size']

            attached_volume = self.build_block_device(blockdevice_id=blockdevice_id, dataset_id=dataset_id,
                                                      volume_size=volume_size, attach_to=attach_to)

            # Fetching the DataIPs and add to iscsi session
            logger.info("Getting all data IPs.")
            data_ips = []
            settings_info = self._rdxapi.get_settings()
            data_ips.append(settings_info[u'iscsi_network1'][u'controller_1_port_1'])
            data_ips.append(settings_info[u'iscsi_network1'][u'controller_2_port_1'])
            data_ips.append(settings_info[u'iscsi_network2'][u'controller_1_port_2'])
            data_ips.append(settings_info[u'iscsi_network2'][u'controller_2_port_2'])

            logging.debug("Listing all data IPs:")
            logging.debug(data_ips[0])
            logging.debug(data_ips[1])
            logging.debug(data_ips[2])
            logging.debug(data_ips[3])

            scsi_tcp_port = settings_info[u'network_configuration'][u'iscsi_target_tcp_port']
            logging.debug("Scsi TCP port is {} .".format(scsi_tcp_port))
            iter_count = 0
            for data_ip in data_ips:
                try:
                    iter_count += 1
                    _manage_session(ip_addr=data_ip, port=scsi_tcp_port)
                    break
                except Exception:
                    if (iter_count == data_ips.__len__()):
                        raise Exception()
                    continue

            logging.debug("Rescanning scsi bus for attached disk")
            rescan_iscsi_session()
            return attached_volume
        except Exception, ex:
            logging.error('An error occurred attaching volume {} to {}: {}'.format(blockdevice_id,
                                                                                   attach_to,
                                                                                   ex))
            raise VolumeAttachFailure(ex)

    def detach_volume(self, blockdevice_id):
        """
        Detach ``blockdevice_id`` from whatever host it is attached to.

        :param blockdevice_id: The unique identifier for the block
            device being detached.
        :return: `None``
        """
        try:
            volumeinfo = self.find_volume_by_blockdevice_id(blockdevice_id)
            volume_name = volumeinfo[u'name']
        except Exception as e:
            logging.error('An error occurred finding the  volume {} : {}'.format(blockdevice_id, e))
            raise UnknownVolume(e)

        try:
            assignmentlist = self.get_assignments_of_volume(blockdevice_id, volume_name)
            logging.debug("Finding paths with device id {} .".format(blockdevice_id))
            paths = find_paths(blockdevice_id)
            for path in paths:
                remove_device(path)

            logger.info("Revoking all hosts assigned to volume {} .".format(volume_name))
            for assignment in assignmentlist:
                logging.debug("Revoking {} .".format(volume_name))
                self._rdxapi.unassign(vol_name=volume_name, host_name=assignment[u'host'])

            rescan_iscsi_session()
            logging.debug("Volume {} successfully detached.".format(blockdevice_id))
        except Exception, ex:
            logging.error('An error occurred while detaching volume {} : {}'.format(blockdevice_id, ex))
            raise Exception(ex)

    def get_assignments_of_volume(self, blockdevice_id, volume_name):
        assignmentlist = self._rdxapi.list_assignments(vol_name=volume_name)
        if (len(assignmentlist) == 0):
            logging.error("Volume {} is not attached to any node/s.".format(volume_name))
            raise UnattachedVolume(blockdevice_id)
        return assignmentlist

    def find_volume_by_blockdevice_id(self, blockdevice_id):
        try:
            volumeinfo = self._rdxapi.find_volume_by_wwid(wwid=blockdevice_id)[0]
            uuid.UUID(volumeinfo[u'description'])
        except Exception as e:
            logging.error("Volume with block-device id {} does not exist.".format(blockdevice_id))
            raise UnknownVolume(blockdevice_id)
        return volumeinfo

    def list_volumes(self):
        try:
            logging.debug("List Volumes started")
            volumes = []
            vol_list = self._rdxapi.list_volumes()
            for vol in vol_list:
                try:
                    dataset_id = uuid.UUID(vol[u'description'])
                except Exception as e:
                    continue

                logging.debug("*****found a dataset")
                attached_to = None
                assignmentlist = self._rdxapi.list_assignments(vol_name=vol[u'name'])
                if (len(assignmentlist) > 0):
                    attached_to = unicode(self._rdxapi.list_hosts(name=assignmentlist[0][u'host'])[0][u'iscsi_name'])

                volumes.append(self.build_block_device(blockdevice_id=unicode(vol[u'wwid']), dataset_id=dataset_id,
                                                       volume_size=vol[u'size'], attach_to=attached_to))
                logging.debug(
                    "found volume {} with dataset id {} assigned with {} .".format(vol[u'name'], vol[u'description'],
                                                                                   attached_to))
            logging.debug("List volumes success")
            return volumes
        except Exception as e:
            logging.error("List volumes failed with error: " + str(e))
            raise ListVolumesFailure(e)

    # def resize_volume(self, blockdevice_id, size):
    #     """
    #     resize the volume , we can support the expand the volume, not shrinking
    #     :param blockdevice_id:
    #     :param size:
    #     :return:
    #     """
    #     volumeinfo = self._rdxapi.find_volume_by_wwid(wwid=blockdevice_id)[0]
    #
    #     try:
    #         dataset_id = uuid.UUID(volumeinfo[u'description'])
    #     except Exception as e:
    #         raise UnknownVolume(blockdevice_id)
    #
    #     volume_name = volumeinfo[u'name']
    #     volume_size = volumeinfo[u'size']
    #
    #     if (volume_size > size):
    #         raise VolumeShrinkFailure("volume size cant be shrink")
    #
    #     self._rdxapi.update_volume(name=volume_name, size=Byte(size).to_GiB().__long__())

    def get_device_path(self, blockdevice_id):
        """
        Get the deivce path based for the blockdevice_id which is WWID fo the volume
        :param blockdevice_id: WWID of the Reduxio Volume
        :return: block device path like /dev/sdb ..
        """
        retries = 0
        while retries < MAX_RESCAN_ATTEMPTS:
            paths = find_paths(blockdevice_id)
            if paths:
                # Just return the first path
                logging.debug("it has path")
                logging.debug(filepath.FilePath(paths[0]).realpath())
                return filepath.FilePath(paths[0]).realpath()
            retries += 1
            logging.info('%s not found, attempt %d', blockdevice_id, retries)
            time.sleep(SLEEP_BWN_RESCAN_IN_S)
        return None


def reduxio_init_from_configuration(cluster_id, rdx_ip, password):
    return ReduxioStorageDriverAPI(
        cluster_id=cluster_id,
        rdx_ip=rdx_ip,
        password=password
    )


def main():
    vs = reduxio_init_from_configuration(cluster_id='1',
                                         rdx_ip="172.17.180.223",
                                         password=u'admin',
                                         )
    vs.destroy_volume(unicode('6F4032F00040000000000000000002AD'))
    # vs.detach_volume(unicode('6F4032F00040000000000000000002AD'))
    # vs.destroy_volume(unicode('6F4032F00040000000000000000002AD'))
    vs.compute_instance_id()
    volume = vs.create_volume(dataset_id=uuid.uuid4(), size=21474836480)
    # vs.list_volumes()
    vm = vs.compute_instance_id()
    vs.attach_volume(blockdevice_id=volume.blockdevice_id, attach_to=vm)
    # vs.list_volumes()
    vs.get_device_path(volume.blockdevice_id)
    # unicode('6000c29efe6df3d5ae7babe6ef9dea74'))
    # vs.compute_instance_id()
    vs.detach_volume(volume.blockdevice_id)
    vs.list_volumes()
    vs.destroy_volume(volume.blockdevice_id)
    # unicode('6000C2915c5df0c12ff0372b8bfb244f'))
    vs.list_volumes()
    # vs.get_device_path(unicode('6000c29efe6df3d5ae7babe6ef9dea74'))


if __name__ == '__main__':
    main()
