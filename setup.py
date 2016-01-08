#!/usr/bin/env python
from setuptools import setup

setup(
        name='boofuzz',
        version='0.0.1.dev.1',
        maintainer='Joshua Pereyda',
        maintainer_email='joshua.t.pereyda@gmail.com',
        url='https://github.com/jtpereyda/boofuzz',
        license='GPL',
        packages=['boofuzz'],
        package_data={'boofuzz': ['web/templates/*', 'web/static/css/*']},
        install_requires=[
            'future', 'pyserial', 'pydot2==1.0.33', 'tornado==4.0.2',
            'Flask==0.10.1', 'impacket'],
        extras_require={
            'testing': ['mock', 'pytest'],
        },
)
