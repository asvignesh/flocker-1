'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
from flocker.node import BackendDescription, DeployerType

from reduxio_flocker_plugin.reduxio_storagedriver import reduxio_init_from_configuration


def api_factory(cluster_id, **kwargs):
    try:
        if kwargs[u'rdx_ip']:
            rdx_ip = kwargs[u'rdx_ip']
        else:
            raise Exception("Agent.yml is not configured properly")

        if kwargs[u'password']:
            rdx_password = kwargs[u'password']
        else:
            raise Exception("Agent.yml is not configured properly")
    except Exception as e:
        raise Exception()
    return reduxio_init_from_configuration(cluster_id=cluster_id,
                                           rdx_ip=rdx_ip,
                                           password=rdx_password)


FLOCKER_BACKEND = BackendDescription(
    name=u"reduxio_flocker_plugin",
    needs_reactor=False, needs_cluster_id=True,
    api_factory=api_factory, deployer_type=DeployerType.block)
