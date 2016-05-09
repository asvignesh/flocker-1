'''
Copyright 2015 VMware, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
from flocker.node import BackendDescription, DeployerType
from reduxio_flocker_plugin.reduxio_storagedriver import reduxio_init_from_configuration


def api_factory(cluster_id, **kwargs):
    return reduxio_init_from_configuration(cluster_id=cluster_id,
                                           vc_ip=kwargs[u'vc_ip'],
                                           username=kwargs[u'username'],
                                           password=kwargs[u'password'],
                                           datacenter_name=kwargs[u'datacenter_name'],
                                           datastore_name=kwargs[u'datastore_name'],
                                           ssl_verify_cert=kwargs[u'ssl_verify_cert'],
                                           ssl_key_file=kwargs[u'ssl_key_file'],
                                           ssl_cert_file=kwargs[u'ssl_cert_file'],
                                           ssl_thumbprint=kwargs[u'ssl_thumbprint'])


FLOCKER_BACKEND = BackendDescription(
    name=u"reduxio_flocker_plugin",  # name isn't actually used for 3rd party plugins
    needs_reactor=False, needs_cluster_id=True,
    api_factory=api_factory, deployer_type=DeployerType.block)
