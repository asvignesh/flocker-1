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
    def __init__(self, cluster_id, rdx_ip, password, chap_user, chap_password):
        logger.info("ReduxioStorageDriverAPI Initializing")

        self._cluster_id = cluster_id
        self._rdx_ip = rdx_ip
        self._password = password
        self._chap_user = chap_user
        self._chap_password = chap_password

        logger.debug("Initializing {}; {};".format(self._cluster_id, self._rdx_ip))

        self._rdxapi = ReduxioAPI(host=rdx_ip, user="rdxadmin", password=password)
        self._rdxhelper = RdxHelper()

        self.initiator_name = get_initiator_name()
        logger.debug("Initiator name is {} .".format(self.initiator_name))

    def compute_instance_id(self):
        """
        :return: the iSCSI Initiator IQN Name
        Sample : iqn.2016-04.com.ubuntu.iscsi:nss3499

        This will be compared against ``BlockDeviceVolume.attached_to``
        to determine which volumes are locally attached and it will be used
        with ``attach_volume`` to locally attach volumes.

        """
        logger.debug('computing instance id!')
        logger.debug('Initiator name is {} .'.format(self.initiator_name))
        return unicode(self.initiator_name)

    def allocation_unit(self):
        """
        Return allocation unit
        """
        logger.debug('Setting minimum allocation unit to Multiplies of 1GiB')
        logger.debug("Reduxio System allocation unit: " +
                     str(int(GiB(1).to_Byte().value)))
        return int(GiB(1).to_Byte().value)

    def _normalize_uuid(self, uuid):
        logger.debug('Normalizing uuid {}'.format(uuid))
        uuid = uuid.translate(None, " -\n'")
        uuid = uuid.lower()
        logger.debug('uuid after normalizing is {}'.format(uuid))
        return uuid

    def create_volume_with_profile(self, dataset_id, size, profile_name):
        """
        :param dataset_id: UUID generate by FLocker
        :param size: size of disk in bytes
        :param profile_name: GOLD / SILVER/ BRONZE
        :return: BlockDeviceVolume struct
        """
        try:
            volume_name = self._rdxhelper._volume_name_from_id(str(dataset_id))
            logger.info(
                "Trying to create volume named {} of size {}GB.".format(volume_name, Byte(size).to_GiB().__long__()))
            self._rdxapi.create_volume(name=volume_name, size=Byte(size).to_GiB().__long__(),
                                       description=str(dataset_id), blocksize=512)
            logger.info("Checking if the volume {} is created.".format(volume_name))
            blockdevice_id = self._rdxapi.find_volume_by_name(name=volume_name)[u'wwid']
            logger.debug("Volume created successfully")
            logger.debug(blockdevice_id)
        except Exception as e:
            logger.error("Cannot create volume because of exception : " + str(e))
            raise VolumeCreationFailure(e)
        volume = self.build_block_device(blockdevice_id=blockdevice_id, dataset_id=dataset_id, volume_size=size)
        logger.debug("vSphere Block Device Volume ID {}".format(volume.blockdevice_id))
        return volume

    def build_block_device(self, blockdevice_id, dataset_id, volume_size, attach_to=None):
        logger.debug(
            'Building blockdevice with blockdevice_id {}, volume_size {}, dataset_id {}, attach_to {}.'.format(
                blockdevice_id, volume_size, dataset_id, attach_to))
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
        logger.info('Creating a Volume of size {} Bytes with dataset id {} .'.format(size, dataset_id))
        try:
            volume_name = self._rdxhelper._volume_name_from_id(str(dataset_id))
            logger.debug(
                "Trying to create volume named {} of size {} GB.".format(volume_name, Byte(size).to_GiB().__long__()))
            self._rdxapi.create_volume(name=volume_name, size=Byte(size).to_GiB().__long__(),
                                       description=str(dataset_id), blocksize=512)
            logger.debug("Checking if the volume {} is created.".format(volume_name))
            blockdevice_id = self._rdxapi.find_volume_by_name(name=volume_name)[u'wwid']
            logger.info("Volume created successfully")
            logger.debug('blockdevice id of the volume {} is {} .'.format(volume_name, blockdevice_id))
        except Exception as e:
            logger.error(
                'Cannot create Volume of size {} Bytes with dataset id {} fails'.format(size, dataset_id))
            logger.error('Exception: ' + str(e))
            raise VolumeCreationFailure(e)
        volume = self.build_block_device(blockdevice_id=blockdevice_id, dataset_id=dataset_id, volume_size=size)
        logger.debug("Block Device Volume ID {}".format(volume.blockdevice_id))
        return volume

    def destroy_volume(self, blockdevice_id):
        """
        Destroy an existing volume.

        :param blockdevice_id: WWID in the reduxio
        :return: None
        """
        logger.info('Destroying the volume with blockdevice id {} .'.format(blockdevice_id))
        try:
            volume_info = self.find_volume_by_blockdevice_id(blockdevice_id)
            volume_name = volume_info[u'name']
            logger.debug('Name of the Volume found is {} .'.format(volume_name))
        except Exception as e:
            logger.error(
                "Unable to find the volume with the provided blockdevice_id {} .".format(blockdevice_id))
            logger.error('Exception: ' + str(e))
            raise UnknownVolume(e)

        try:
            logger.debug("Checking if the volume {} is attached to any node/s.".format(volume_name))
            assignment_list = self._rdxapi.list_assignments(vol_name=volume_name)
            if (len(assignment_list) > 0):
                logger.error("Volume {} is attached to a node, so it cannot be destroyed.".format(volume_name))
                raise VolumeAttached(blockdevice_id)

            # volume_name = self._rdxhelper._volume_name_from_id(str(dataset_id))
            logger.debug("Trying to delete the volume {} .".format(volume_name))
            self._rdxapi.delete_volume(name=volume_name)
            logger.info("Volume {} deleted successfully.".format(volume_name))
        except Exception as e:
            logger.error("Destroy Volume {} failed.".format(volume_name))
            logger.error('Exception: ' + str(e))
            raise VolumeDestroyFailure(e)

    def attach_volume(self, blockdevice_id, attach_to):
        """
        Attach an existing volume to an initiator.

        If host is not created, it will create the host
        :param blockdevice_id: WWID of the reduxio Volume
        :param attach_to: is the value generated by the compute_instance_id ... here IQN of the current node
        :return: BlockDeviceVolume with attachd_to
        """

        logger.info("Attaching Volume with blockdevice id {} with iscsi target {}".format(blockdevice_id, attach_to))
        try:
            volume_info = self.find_volume_by_blockdevice_id(blockdevice_id)
            dataset_id = uuid.UUID(volume_info[u'description'])
            volume_name = volume_info[u'name']
            logger.debug('Found the Volume, Volume name is {}, dataset id is {} .'.format(volume_name, dataset_id))
        except Exception as e:
            logger.error(
                'An error occured finding the volume with blockdevice id {} .'.format(blockdevice_id))
            logger.error('Exception: ' + str(e))
            raise UnknownVolume(e)

        try:
            logger.info("Checking if the volume {} is attached to any node/s".format(volume_name))
            assignmentlist = self._rdxapi.list_assignments(vol_name=volume_name)
            if len(assignmentlist) > 0:
                logger.error("Volume {} is already attached to a node.".format(volume_name))
                raise AlreadyAttachedVolume(blockdevice_id)

            hostname = None
            logger.debug('Listing all the hosts.')
            host_list = self._rdxapi.list_hosts()
            logger.debug("Checking if the host with iscsi name {} already exist.".format(attach_to))
            for host in host_list:
                if attach_to == host[u'iscsi_name']:
                    hostname = host[u'name']
                    logger.debug('Host with iscsi name {} exists, Host name is {}'.format(attach_to, hostname))
                    break

            if hostname is None:
                logger.debug('Host not found, must be created.')
                hostname = self._rdxhelper._host_name()
                logger.debug(
                    "Trying to create host {} with iscsi name {} since it does not exist.".format(hostname, attach_to))
                self._rdxapi.create_host(name=hostname,
                                         iscsi_name=attach_to,
                                         user_chap=self._chap_user,
                                         pwd_chap=self._chap_password)

            logger.debug("Trying to assign host {} to volume {} .".format(hostname, volume_name))
            self._rdxapi.assign(vol_name=volume_name, host_name=hostname)
            volume_size = volume_info[u'size']

            attached_volume = self.build_block_device(blockdevice_id=blockdevice_id, dataset_id=dataset_id,
                                                      volume_size=volume_size, attach_to=attach_to)
            logger.info('Assigning host {} to volume {} is successful.'.format(hostname, volume_name))
            # Fetching the DataIPs and add to iscsi session
        except Exception as ex:
            logger.error('An error occurred attaching volume {} to {}'.format(blockdevice_id, attach_to))
            logger.error('Exception: ' + str(ex))
            raise VolumeAttachFailure(ex)
        try:
            logger.debug("Getting all data IPs.")
            data_ips = []
            settings_info = self._rdxapi.get_settings()
            data_ips.append(settings_info[u'iscsi_network1'][u'controller_1_port_1'])
            data_ips.append(settings_info[u'iscsi_network1'][u'controller_2_port_1'])
            data_ips.append(settings_info[u'iscsi_network2'][u'controller_1_port_2'])
            data_ips.append(settings_info[u'iscsi_network2'][u'controller_2_port_2'])

            logger.debug("Listing all data IPs:")
            logger.debug(data_ips[0])
            logger.debug(data_ips[1])
            logger.debug(data_ips[2])
            logger.debug(data_ips[3])

            scsi_tcp_port = settings_info[u'network_configuration'][u'iscsi_target_tcp_port']
            logger.debug("Scsi TCP port is {} .".format(scsi_tcp_port))
            iter_count = 0
            for data_ip in data_ips:
                try:
                    iter_count += 1
                    _manage_session(ip_addr=data_ip,
                                    port=scsi_tcp_port,
                                    chap_user=self._chap_user,
                                    chap_password=self._chap_password)
                    break
                except Exception:
                    logger.debug(
                        'Failed to discover targets with data ip {}, will continue with next data ip.'.format(data_ip))
                    if iter_count == data_ips.__len__():
                        logger.error('No more data ips, Target discovery failed.')
                        raise Exception()
                    continue
            rescan_iscsi_session()
        except Exception as exc:
            logger.error('An error occurred while discovering the attached volume. reverting back...')
            logger.error("Exception: {}".format(str(exc)))
            try:
                self._rdxapi.unassign(vol_name=volume_name, host_name=hostname)
                logger.error('Revert successful.')
            except Exception as ex:
                logger.error('Error occurred while reverting, Exception: {}'.format(str(ex)))
        return attached_volume

    def detach_volume(self, blockdevice_id):
        """
        Detach ``blockdevice_id`` from whatever host it is attached to.

        :param blockdevice_id: The unique identifier for the block
            device being detached.
        :return: `None``
        """
        logger.info('detaching Volume with blockdevice id {} .'.format(blockdevice_id))
        try:
            volumeinfo = self.find_volume_by_blockdevice_id(blockdevice_id)
            volume_name = volumeinfo[u'name']
            logger.debug('Found the volume, volume name is {} .'.format(volume_name))
        except Exception as e:
            logger.error('An error occurred finding the  volume {} .'.format(blockdevice_id))
            logger.error('Exception: ' + str(e))
            raise UnknownVolume(e)

        try:
            assignmentlist = self.get_assignments_of_volume(blockdevice_id, volume_name)
            paths = find_paths(blockdevice_id)
            for path in paths:
                remove_device(path)

            logger.info("Revoking all hosts assigned to volume {} .".format(volume_name))
            for assignment in assignmentlist:
                logger.debug("Revoking {} .".format(volume_name))
                self._rdxapi.unassign(vol_name=volume_name, host_name=assignment[u'host'])

            rescan_iscsi_session()
            logger.debug("Volume {} successfully detached.".format(blockdevice_id))
        except Exception as ex:
            logger.error('An error occurred while detaching volume {} .'.format(blockdevice_id))
            logger.error('Exception: ' + str(ex))
            raise Exception(ex)

    def get_assignments_of_volume(self, blockdevice_id, volume_name):
        logger.debug('Getting the list of hosts assigned to volume {} .'.format(volume_name))
        assignmentlist = self._rdxapi.list_assignments(vol_name=volume_name)
        if (len(assignmentlist) == 0):
            logger.error("Volume {} is not attached to any node.".format(volume_name))
            raise UnattachedVolume(blockdevice_id)
        logger.debug('Fetched the list of hosts assigned to volume {} .'.format(volume_name))
        return assignmentlist

    def find_volume_by_blockdevice_id(self, blockdevice_id):
        logger.debug('Trying to find the volume by blockdevice_id {} .'.format(blockdevice_id))
        try:
            volumeinfo = self._rdxapi.find_volume_by_wwid(wwid=blockdevice_id)[0]
            uuid.UUID(volumeinfo[u'description'])
        except Exception as e:
            logger.error("Volume with blockdevice id {} does not exist.".format(blockdevice_id))
            raise UnknownVolume(blockdevice_id)
        logger.debug('Found a Volume with blockdevice id {} .'.format(blockdevice_id))
        return volumeinfo

    def list_volumes(self):
        logger.info("List Volumes started")
        try:
            volumes = []
            vol_list = self._rdxapi.list_volumes()
            assign_list = self._rdxapi.list_assignments()
            hosts_list = self._rdxapi.list_hosts()
            vol_mapper = {}
            host_mapper = {}
            for host in hosts_list:
                host_mapper[host[u'name']] = host
            for assign in assign_list:
                if assign[u'vol'] not in vol_mapper:
                    vol_mapper[assign[u'vol']] = []
                vol_mapper[assign[u'vol']].append(assign[u'host'])
                # vol_mapper is dic with volumename as key and host assignment list of that volumename as it's pair.
                # alternate for list assignment by volume
            for vol in vol_list:
                try:
                    logger.debug('Finding dataset id from description of Volume {} .'.format(vol[u'name']))
                    dataset_id = uuid.UUID(vol[u'description'])
                    logger.debug('Found dataset id {} in Volume {} .'.format(dataset_id, vol[u'name']))
                except Exception as e:
                    logger.error('Error getting dataset id, continue with next Volume.')
                    continue

                attached_to = None
                # logger.debug('Getting the list of Hosts assigned to Volume {} .'.format(vol[u'name']))
                if vol[u'name'] in vol_mapper:
                    attached_to = unicode(host_mapper[vol_mapper[vol[u'name']][0]][u'iscsi_name'])
                    logger.debug("iscsi name of the host {} is {} .".format(vol_mapper[vol[u'name']][0], attached_to))
                # assignmentlist = self._rdxapi.list_assignments(vol_name=vol[u'name'])
                # if (len(assignmentlist) > 0):
                #     attached_to = unicode(self._rdxapi.list_hosts(name=assignmentlist[0][u'host'])[0][u'iscsi_name'])

                volumes.append(self.build_block_device(blockdevice_id=unicode(vol[u'wwid']), dataset_id=dataset_id,
                                                       volume_size=vol[u'size'], attach_to=attached_to))
                logger.debug(
                    "found volume {} with dataset id {} assigned with {} .".format(vol[u'name'], vol[u'description'],
                                                                                   attached_to))
            logger.info("List volumes successful")
            return volumes
        except Exception as e:
            logger.error("List volumes failed with Exception: " + str(e))
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
        logger.debug('Getting device path of Volume with blockdevice id {} .'.format(blockdevice_id))
        retries = 0
        while retries < MAX_RESCAN_ATTEMPTS:
            paths = find_paths(blockdevice_id)
            if paths:
                # Just return the first path
                logger.debug("it has path")
                logger.debug("{} with realpath: {}".format(filepath.FilePath(paths[0]),
                                                           filepath.FilePath(paths[0]).realpath()))
                return filepath.FilePath(paths[0]).realpath()
            retries += 1
            logger.debug('%s not found, attempt %d', blockdevice_id, retries)
            time.sleep(SLEEP_BWN_RESCAN_IN_S)
        return None


def reduxio_init_from_configuration(cluster_id, rdx_ip, password, chap_user, chap_password):
    logger.debug('Initializing Reduxio...')
    return ReduxioStorageDriverAPI(
        cluster_id=cluster_id,
        rdx_ip=rdx_ip,
        password=password,
        chap_user=chap_user,
        chap_password=chap_password
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
