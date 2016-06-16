'''
Copyright 2016 Reduxio, Inc.  All rights reserved.
'''
#!/usr/bin/env python3

import paramiko
import json
import datetime
import time

import logging

from exceptions import *

CONNECTION_RETRY_NUM = 5

VOLUMES = "volumes"
HOSTS = "hosts"
HG_DIR = "hostgroups"
NEW_COMMAND = "new"
UPDATE_COMMAND = "update"
LS_COMMAND = "ls"
DELETE_COMMAND = "delete"
LIST_ASSIGN_CMD = "list-assignments"
CLI_DATE_FORMAT = "%m-%Y-%d %H:%M:%S"
CONNECT_LOCK_NAME = "reduxio_cli_Lock"
CLI_CONNECTION_RETRY_SLEEP = 5
CLI_SSH_CMD_TIMEOUT = 20
CLI_CONNECT_TIMEOUT = 50

logging = logging.getLogger(__name__)


class RdxAPIConnectionException(Exception):
    """
    connection to reduxio failed
    """


class RdxAPICommandException(Exception):
    """
    command exec exception
    """


class RdxApiCmd(object):
    def __init__(self, cmd_prefix, argument=None, flags=None, boolean_flags=None, force=None):
        if isinstance(cmd_prefix, list):
            cmd_prefix = map(lambda x: x.strip(), cmd_prefix)
            self.cmd = " ".join(cmd_prefix)
        else:
            self.cmd = cmd_prefix

        self.arg = None
        self.flags = {}
        self.booleanFlags = {}

        if argument is not None:
            self.argument(argument)

        if flags is not None:
            if isinstance(flags, list):
                for flag in flags:
                    self.flag(flag[0], flag[1])
            else:
                for key in flags:
                    self.flag(key, flags[key])

        if boolean_flags is not None:
            for flag in boolean_flags:
                self.boolean_flag(flag)

        if force:
            self.force()

    def argument(self, value):
        self.arg = value

    def flag(self, name, value):
        if value is not None:
            self.flags[name.strip()] = value

    def boolean_flag(self, name):
        if name is not None:
            self.booleanFlags[name.strip()] = True

    def build(self):
        argument_str = "" if self.arg is None else self.arg
        flags_str = ""

        for key in sorted(self.flags):
            flags_str += " -{} \"{}\"".format(key, self.flags[key])

        for booleanFlag in sorted(self.booleanFlags):
            flags_str += " -{}".format(booleanFlag)

        return "{} {}{}".format(self.cmd, argument_str, flags_str)

    def force(self):
        self.boolean_flag("force")

    def json(self):
        self.flag("output", "json")

    def __str__(self):
        return self.build()

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            # print("self: " + str(self).strip())
            # print("othe: " + str(other).strip())
            return str(self).strip() == str(other).strip()
        else:
            return False


class ReduxioAPI(object):
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.ssh = None  # type: paramiko.SSHClient
        self._connect()

    def _reconnect_if_needed(self):
        if not self.connected:
            self._connect()

    def _connect(self):
        logging.info("signin to Reduxio api client.")
        self.connected = False
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(self.host, username=self.user, password=self.password, timeout=CLI_CONNECT_TIMEOUT)
            self.connected = True
        except paramiko.ssh_exception.AuthenticationException:
            raise RdxAPIConnectionException("Authentication Error. Check login credentials")
        except Exception as e:
            logging.error(str)
            raise RdxAPIConnectionException(
                "Failed to create ssh connection to Reduxio. Please check network connection or Reduxio hostname/IP.")

    # @utils.synchronized(CONNECT_LOCK_NAME, external=True)
    def _run_cmd(self, cmd):
        cmd.json()
        logging.info("Running cmd: {}".format(cmd))
        success = False
        for x in range(1, CONNECTION_RETRY_NUM):
            try:
                self._reconnect_if_needed()
                stdin, stdout, stderr = self.ssh.exec_command(command=str(cmd), timeout=CLI_SSH_CMD_TIMEOUT)
                success = True
                break
            except Exception as e:
                logging.error(str(e))
                logging.error("Failed running cli command, retrying({}/{})".format(x, CONNECTION_RETRY_NUM))
                self.connected = False
                time.sleep(CLI_CONNECTION_RETRY_SLEEP)

        if not success:
            raise RdxAPIConnectionException(
                "Failed to connect to Redxuio CLI. Check your username,password or Reduxio Hostname/IP")

        str_out = stdout.read()
        data = json.loads(str_out.decode('utf-8'))

        if stdout.channel.recv_exit_status() != 0:
            logging.error("Failed running cli command: {}".format(data["msg"]))
            raise RdxAPICommandException(data["msg"])

        # logging.debug("Command output is: {}".format(str_out))

        return data["data"]

    @staticmethod
    def utc_to_cli_date(utc_date):
        if utc_date is None: return None
        date = datetime.datetime.fromtimestamp(utc_date)
        return date.strftime(CLI_DATE_FORMAT)

    ################################################################
    ############################ Volumes ###########################
    ################################################################

    def create_volume(self, name, size, description=None, historypolicy=None, blocksize=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, NEW_COMMAND])

        cmd.argument(name)
        cmd.flag("size", size)
        cmd.flag("description", description)
        cmd.flag("policy", historypolicy)
        cmd.flag("blocksize", blocksize)

        self._run_cmd(cmd)

    def list_volumes(self):
        return self._run_cmd(RdxApiCmd(cmd_prefix=[VOLUMES, LS_COMMAND]))["volumes"]

    def list_clones(self, name):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "list-clones"])

        cmd.argument(name)

        return self._run_cmd(cmd)

    def find_volume_by_name(self, name):
        cmd = RdxApiCmd(cmd_prefix=[LS_COMMAND, VOLUMES + "/" + name])

        return self._run_cmd(cmd)["volumes"][0]

    def find_volume_by_wwid(self, wwid):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "find-by-wwid"])

        cmd.argument(wwid)

        return self._run_cmd(cmd)

    def delete_volume(self, name):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, DELETE_COMMAND])

        cmd.argument(name)
        cmd.force()

        return self._run_cmd(cmd)

    def update_volume(self, name, new_name=None, description=None, size=None, history_policy=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, UPDATE_COMMAND])

        cmd.argument(name)
        cmd.flag("size", size)
        cmd.flag("new-name", new_name)
        cmd.flag("policy", history_policy)
        cmd.flag("size", size)
        cmd.flag("description", description)

        self._run_cmd(cmd)

    def revert_volume(self, name, utc_date=None, bookmark_name=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "revert"])

        cmd.argument(name)
        cmd.flag("timestamp", ReduxioAPI.utc_to_cli_date(utc_date))
        cmd.flag("bookmark", bookmark_name)
        cmd.force()

        return self._run_cmd(cmd)

    def clone_volume(self, parent_name, clone_name, utc_date=None, str_date=None, bookmark_name=None, description=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "clone"])

        cmd.argument(parent_name)
        cmd.flag("name", clone_name)
        if str_date is not None:
            cmd.flag("timestamp", str_date)
        else:
            cmd.flag("timestamp", ReduxioAPI.utc_to_cli_date(utc_date))
        cmd.flag("bookmark", bookmark_name)
        cmd.flag("description", description)

        self._run_cmd(cmd)

    def list_vol_bookmarks(self, vol):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "list-bookmarks"])

        cmd.argument(vol)

        return self._run_cmd(cmd)

    def add_vol_bookmark(self, vol, bm_name, utc_date=None, str_date=None, bm_type=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "bookmark"])

        cmd.argument(vol)
        cmd.flag("name", bm_name)
        if str_date is not None:
            cmd.flag("timestamp", str_date)
        else:
            cmd.flag("timestamp", ReduxioAPI.utc_to_cli_date(utc_date))
        cmd.flag("type", bm_type)

        return self._run_cmd(cmd)

    def delete_vol_bookmark(self, vol, bm_name):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "delete-bookmark"])

        cmd.argument(vol)
        cmd.flag("name", bm_name)

        return self._run_cmd(cmd)

    ################################################################
    ############################ Hosts #############################
    ################################################################

    def list_hosts(self, name=None):
        if (name == None):
            return self._run_cmd(RdxApiCmd(cmd_prefix=[HOSTS, LS_COMMAND]))["hosts"]
        else:
            return self._run_cmd(RdxApiCmd(cmd_prefix=[HOSTS, LS_COMMAND, name]))["hosts"]

    def create_host(self, name, iscsi_name, description=None, user_chap=None, pwd_chap=None):
        cmd = RdxApiCmd(cmd_prefix=[HOSTS, NEW_COMMAND])

        cmd.argument(name)
        cmd.flag("iscsi-name", iscsi_name)
        cmd.flag("description", description)
        cmd.flag("user-chap", user_chap)
        cmd.flag("pwd-chap", pwd_chap)

        return self._run_cmd(cmd)

    def delete_host(self, name):
        cmd = RdxApiCmd(cmd_prefix=[HOSTS, DELETE_COMMAND])

        cmd.argument(name)
        cmd.force()

        return self._run_cmd(cmd)

    def update_host(self, name, new_name=None, description=None, user_chap=None, pwd_chap=None):
        cmd = RdxApiCmd(cmd_prefix=[HOSTS, UPDATE_COMMAND])

        cmd.argument(name)
        cmd.flag("new-name", new_name)
        cmd.flag("user-chap", user_chap)
        cmd.flag("pwd-chap", pwd_chap)
        cmd.flag("description", description)

        return self._run_cmd(cmd)

    ################################################################
    ########################## HostGroups ##########################
    ################################################################

    def list_hostgroups(self):
        return self._run_cmd(RdxApiCmd(cmd_prefix=[HG_DIR, LS_COMMAND]))["hostgroups"]

    def create_hostgroup(self, name, description=None):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, NEW_COMMAND])

        cmd.argument(name)
        cmd.flag("description", description)

        return self._run_cmd(cmd)

    def delete_hostgroup(self, name):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, DELETE_COMMAND])

        cmd.argument(name)
        cmd.force()

        return self._run_cmd(cmd)

    def update_hostgroup(self, name, new_name=None, description=None):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, UPDATE_COMMAND])

        cmd.argument(name)
        cmd.flag("new-name", new_name)
        cmd.flag("description", description)

        return self._run_cmd(cmd)

    def list_hosts_in_hostgroup(self, name):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, "list-hosts"])
        cmd.argument(name)

        return self._run_cmd(cmd)

    def add_host_to_hostgroup(self, name, host_name):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, "add-host"])
        cmd.argument(name)
        cmd.flag("host", host_name)

        return self._run_cmd(cmd)

    def remove_host_from_hostgroup(self, name, host_name):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, "remove-host"])
        cmd.argument(name)
        cmd.flag("host", host_name)

        return self._run_cmd(cmd)

    def add_hg_bookmark(self, hg_name, bm_name, utc_date=None, str_date=None, bm_type=None):
        cmd = RdxApiCmd(cmd_prefix=[HG_DIR, "add-bookmark"])

        cmd.argument(hg_name)
        cmd.flag("name", bm_name)
        if str_date is not None:
            cmd.flag("timestamp", str_date)
        else:
            cmd.flag("timestamp", ReduxioAPI.utc_to_cli_date(utc_date))
        cmd.flag("type", bm_type)

        return self._run_cmd(cmd)

    ################################################################
    ########################## Assignments #########################
    ################################################################

    def assign(self, vol_name, host_name=None, hostgroup_name=None, lun=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "assign"])

        cmd.argument(vol_name)
        cmd.flag("host", host_name)
        cmd.flag("group", hostgroup_name)
        cmd.flag("lun", lun)

        return self._run_cmd(cmd)

    def unassign(self, vol_name, host_name=None, hostgroup_name=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, "unassign"])

        cmd.argument(vol_name)
        cmd.flag("host", host_name)
        cmd.flag("group", hostgroup_name)

        return self._run_cmd(cmd)

    def list_assignments(self, vol_name=None, host=None, hg=None):
        cmd = RdxApiCmd(cmd_prefix=[VOLUMES, LIST_ASSIGN_CMD])
        if not vol_name is None:
            cmd.argument(vol_name)
        elif not host is None:
            cmd = RdxApiCmd(cmd_prefix=[HOSTS, LIST_ASSIGN_CMD])
            cmd.argument(host)
        elif not host is None:
            cmd = RdxApiCmd(cmd_prefix=[HG_DIR, LIST_ASSIGN_CMD])
            cmd.argument(hg)

        return self._run_cmd(cmd)

    ################################################################
    ########################## Settings ############################
    ################################################################

    def get_settings(self):
        cli_hash = self._run_cmd(RdxApiCmd(cmd_prefix=["settings", LS_COMMAND]))
        return self._translate_settings_to_hash(cli_hash)

    @staticmethod
    def _translate_settings_to_hash(cli_hash):
        new_hash = {}
        for key, value in cli_hash.iteritems():
            if key == "directories":
                continue
            if key == "email_recipient_list":
                continue

            new_hash[key] = {}
            for inter_hash in value:
                if "Name" in inter_hash:
                    new_hash[key][inter_hash["Name"]] = inter_hash["value"]
                else:
                    new_hash[key][inter_hash["name"]] = inter_hash["value"]
        return new_hash


def main():
    name = "test1rdx1"

    vs = ReduxioAPI(host="172.17.180.223", user="rdxadmin", password="admin")
    vs.get_settings()
    # vs.create_volume(name=name, size="10")
    # vs.delete_volume(name=name)

    # volume = vs.create_volume(dataset_id=uuid.uuid4(), size=21474836480)
    # vs.list_volumes()
    # vm = vs.compute_instance_id()
    # vs.attach_volume(blockdevice_id=volume.blockdevice_id, attach_to=vm)
    # vs.list_volumes()
    # vs.get_device_path(volume.blockdevice_id)
    # # unicode('6000c29efe6df3d5ae7babe6ef9dea74'))
    # # vs.compute_instance_id()
    # vs.detach_volume(volume.blockdevice_id)
    # vs.list_volumes()
    # vs.destroy_volume(volume.blockdevice_id)
    # # unicode('6000C2915c5df0c12ff0372b8bfb244f'))
    # vs.list_volumes()
    # vs.get_device_path(unicode('6000c29efe6df3d5ae7babe6ef9dea74'))


if __name__ == '__main__':
    main()
