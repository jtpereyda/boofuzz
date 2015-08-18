#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


setup(
    name='Sulley',
    download_url='https://github.com/OpenRCE/sulley',
    packages=['requests', 'sulley', 'sulley.legos', 'sulley.pgraph', 'sulley.utils',
              'unit_tests', 'utils', 'web'],
    package_dir={'requests': './requests',
                 'sulley': './sulley',
                 'sulley.legos': './sulley/legos',
                 'sulley.pgraph': './sulley/pgraph',
                 'sulley.utils': './sulley/utils',
                 'unit_tests': './unit_tests',
                 'utils': './utils',
                 'web': './web'
                 },
    package_data={'web': ['templates/*', 'static/css/*']},
    install_requires=['pydot2==1.0.33', 'tornado==4.0.2', 'Flask==0.10.1', 'pcapy', 'impacket']
    install_requires=['pydot2==1.0.33', 'tornado==4.0.2', 'Flask==0.10.1']
)
