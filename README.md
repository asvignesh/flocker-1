Reduxio Systems Backend Plugin for ClusterHQ/Flocker

Preinstallation
(Ubuntu 14.04)
apt-get -y install open-iscsi multipath-tools lsscsi

(CentOS or RHEL)
yum ­y install lsscsi iscsi-initiator-utils device-mapper device-mapper-event-libs device-mapper-multipath

Installation
sudo /opt/flocker/bin/pip install git+https://github.com/reduxio/flocker.git