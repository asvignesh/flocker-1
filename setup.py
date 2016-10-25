'''
Copyright 2016 Reduxio, Inc.  All rights reserved.  Licensed under the Apache v2 License.
'''
from setuptools import setup

setup(
    name="Reduxio StorKit Flocker",
    packages=[
        "reduxio_storkit_flocker"
    ],
    package_data={
        "reduxio_storkit_flocker": ["config/*"],
    },
    version="1.0",
    description="Reduxio Storage Plugin for ClusterHQ/Flocker.",
    author="Vignesh",
    author_email="",
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 1 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='reduxio, backend, plugin, flocker, docker, python',
    url="",
    install_requires=[
        "paramiko>=2.0.0"
    ]
)
