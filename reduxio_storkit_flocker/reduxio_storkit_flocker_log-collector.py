from gzip import open as gzip_open
from platform import dist as platform_dist
from shutil import copyfileobj, make_archive, rmtree, copyfile
from socket import gethostname
from subprocess import check_call, check_output
from uuid import uuid1
from flocker import __version__
import os
import glob
import re
import sys


def gzip_file(source_path, archive_path):
    """
    Create a gzip compressed archive of ``source_path`` at ``archive_path``.
    An empty archive file will be created if the source file does not exist.
    This gives the diagnostic archive a consistent set of files which can
    easily be tested.
    """
    with gzip_open(archive_path, 'wb') as archive:
        if os.path.isfile(source_path):
            with open(source_path, 'rb') as source:
                copyfileobj(source, archive)


def list_hardware():
    """
    List the hardware on the local machine.

    :returns: ``bytes`` JSON encoded hardware inventory of the current host.
    """
    with open(os.devnull, 'w') as devnull:
        return check_output(
            ['lshw', '-quiet', '-json'],
            stderr=devnull
        )


def get_files_with_regex(regex):
    for filename in glob.glob(regex):
        yield filename


class GetReduxioFlockerPluginLogs(object):
    def __init__(self, service_manager, log_exporter):
        self._service_manager = service_manager
        self._log_exporter = log_exporter
        self._suffix = unicode(uuid1())
        self._archive_name = "ReduxioStorkitFlocker_driver_logs_{}".format(self._suffix)
        self._archive_path = os.path.abspath(self._archive_name)
        self._args = ["--flocker-log", "--docker-log", "--application-log", "--sys-log", "--all"]

    def _logfile_path(self, name):
        return os.path.join(self._archive_name,
                            name,
                            )

    def _open_logfile(self, name):
        return open(self._logfile_path(name), 'w')

    def get_reduxio_logs(self):
        regex = '/var/log/reduxio_storkit_flocker.log*'
        for filename in get_files_with_regex(regex=regex):
            log_filename = filename.split('/')
            log_filename = log_filename[-1]
            # log_file_path = self._logfile_path(log_filename.replace('.', '_') + '_rdx.gz')
            if filename.endswith('.gz'):
                copyfile(filename, os.path.join(self._archive_path, log_filename, ))
            else:
                log_filename = log_filename.replace('.', '_')
                gzip_file(filename, os.path.join(self._archive_path, log_filename + '.gz', ))

    def create(self):
        os.makedirs(self._archive_path)
        args = sys.argv
        if not args[1:]:
            args.append("--all")
        for arg in args[1:]:
            if arg not in self._args:
                return ("Illegal argument,\n"
                        "--docker-log               Docker logs"
                        "\n--flocker-log            Flocker logs\n"
                        "--application-log          Reduxio-StorKit-Flocker logs\n"
                        "--sys-log                  system logs along with other system information\n"
                        "--all                      all logs including Flocker diagnosticlogs\n")

        try:
            if "--docker-log" in args or "--all" in args:
                # Docker Logs
                self._log_exporter.export_docker(service_name='docker', target_path=self._archive_path)

                # Docker version
                check_call(
                    ['docker', 'version'],
                    stdout=self._open_logfile('docker-version')
                )

                # Docker configuration
                check_call(
                    ['docker', 'info'],
                    stdout=self._open_logfile('docker-info')
                )

            if "--application-log" in args or "--all" in args:
                # Reduxio Flocker Driver Logs
                self.get_reduxio_logs()

            if "--flocker-log" in args or "--all" in args:
                # Flocker version
                with self._open_logfile('flocker-version') as output:
                    output.write(__version__.encode('utf-8') + b'\n')

                # Flocker logs.
                services = self._service_manager.flocker_services()
                for service_name, service_status in services:
                    self._log_exporter.export_flocker(
                        service_name=service_name,
                        target_path=self._logfile_path(service_name)
                    )

            if "--sys-log" in args or "--all" in args:
                # Syslog.
                self._log_exporter.export_all(self._logfile_path('syslog'))

                # Status of all services.
                with self._open_logfile('service-status') as output:
                    services = self._service_manager.all_services()
                    for service_name, service_status in services:
                        output.write(service_name + " " + service_status + "\n")

                # Kernel version
                self._open_logfile('uname').write(' '.join(os.uname()))

                # Distribution version
                self._open_logfile('os-release').write(
                    open('/etc/os-release').read()
                )

                # Network configuration
                check_call(
                    ['ip', 'addr'],
                    stdout=self._open_logfile('ip-addr')
                )

                # Hostname
                self._open_logfile('hostname').write(gethostname() + '\n')

                # Partition information
                check_call(
                    ['fdisk', '-l'],
                    stdout=self._open_logfile('fdisk')
                )

                # Block Device and filesystem information
                check_call(
                    ['lsblk', '--all'],
                    stdout=self._open_logfile('lsblk')
                )

                # Hardware inventory
                self._open_logfile('lshw').write(list_hardware())

            # Create a single archive file
            archive_path = make_archive(
                base_name=self._archive_name,
                format='tar',
                root_dir=os.path.dirname(self._archive_path),
                base_dir=os.path.basename(self._archive_path),
            )
        finally:
            # Attempt to remove the source directory.
            rmtree(self._archive_path)
        return archive_path


class SystemdServiceManager(object):
    """
    List services managed by Systemd.
    """

    def all_services(self):
        """
        Iterate the name and status of all services known to SystemD.
        """
        output = check_output(['systemctl', 'list-unit-files', '--no-legend'])
        for line in output.splitlines():
            line = line.rstrip()
            service_name, service_status = line.split(None, 1)
            yield service_name, service_status

    def flocker_services(self):
        """
        Iterate the name and status of the Flocker services known to SystemD.
        """
        service_pattern = r'^(?P<service_name>flocker-.+)\.service'
        for service_name, service_status in self.all_services():
            match = re.match(service_pattern, service_name)
            if match:
                service_name = match.group('service_name')
                if service_status == 'enabled':
                    yield service_name, service_status


class UpstartServiceManager(object):
    """
    List services managed by Upstart.
    """

    def all_services(self):
        """
        Iterate the name and status of all services known to Upstart.
        """
        for line in check_output(['initctl', 'list']).splitlines():
            service_name, service_status = line.split(None, 1)
            yield service_name, service_status

    def flocker_services(self):
        """
        Iterate the name and status of the Flocker services known to Upstart.
        """
        for service_name, service_status in self.all_services():
            if service_name.startswith('flocker-'):
                yield service_name, service_status


class JournaldLogExporter(object):
    """
    Export logs managed by JournalD.
    """

    def export_docker(self, service_name, target_path):
        """
        Export logs for ``service_name`` to ``target_path`` compressed using
        ``gzip``.
        """
        # Centos-7 doesn't have separate startup logs.
        open(target_path + '/docker_startup.gz', 'w').close()
        check_call(
            'journalctl --all --output cat --unit {}.service '
            '| gzip'.format(service_name),
            stdout=open(target_path + '/docker_log_eliot.gz', 'w'),
            stderr=open(target_path + '/docker_log_eliot.gz', 'w'),
            shell=True
        )

    def export_flocker(self, service_name, target_path):
        """
        Export logs for ``service_name`` to ``target_path`` compressed using
        ``gzip``.
        """
        # Centos-7 doesn't have separate startup logs.
        open(target_path + '_startup.gz', 'w').close()
        check_call(
            'journalctl --all --output cat --unit {}.service '
            '| gzip'.format(service_name),
            stdout=open(target_path + '_eliot.gz', 'w'),
            shell=True
        )

    def export_all(self, target_path):
        """
        Export all system logs to ``target_path`` compressed using ``gzip``.
        """
        check_call(
            'journalctl --all --boot | gzip',
            stdout=open(target_path + '.gz', 'w'),
            shell=True
        )


class UpstartLogExporter(object):
    """
    Export logs for services managed by Upstart and written by RSyslog.
    """

    def export_docker(self, service_name, target_path):
        docker_path_regex = "/var/log/upstart/{}.log*".format(service_name)
        for filename in get_files_with_regex(regex=docker_path_regex):
            log_filename = filename.split('/')
            log_filename = log_filename[-1]
            if filename.endswith('.gz'):
                copyfile(filename, os.path.join(target_path, log_filename, ))
            else:
                log_filename = log_filename.replace('.', '_')
                gzip_file(filename, os.path.join(target_path, log_filename + '.gz', ))

    def export_flocker(self, service_name, target_path):
        """
        Export logs for ``service_name`` to ``target_path`` compressed using
        ``gzip``.
        """
        files = [
            ("/var/log/upstart/{}.log".format(service_name),
             target_path + '_startup.gz'),
            ("/var/log/flocker/{}.log".format(service_name),
             target_path + '_eliot.gz'),
        ]
        for source_path, archive_path in files:
            gzip_file(source_path, archive_path)

    def export_all(self, target_path):
        """
        Export all system logs to ``target_path`` compressed using ``gzip``.
        """
        gzip_file('/var/log/syslog', target_path + '.gz')


def current_distribution():
    """
    :returns: A ``str`` label for the operating system distribution running
        this script.
    """
    name, version, _ = platform_dist()
    return name.lower() + '-' + version


def main():
    distrib = current_distribution()
    if "ubuntu-14.04" in distrib:
        print GetReduxioFlockerPluginLogs(service_manager=UpstartServiceManager(),
                                          log_exporter=UpstartLogExporter()).create()
    elif "centos" in distrib or "redhat" in distrib:
        print GetReduxioFlockerPluginLogs(service_manager=SystemdServiceManager(),
                                          log_exporter=JournaldLogExporter()).create()


if __name__ == "__main__":
    main()
