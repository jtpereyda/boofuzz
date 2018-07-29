#!/usr/bin/env python
import ast
import os
import re

from setuptools import setup, find_packages

setup_dir = os.path.abspath(os.path.dirname(__file__))


def find_version(*path_elements):
    """Search a file for `__version__ = 'version number'` and return version.

    @param path_elements: Arguments specifying file to search.

    @return: Version number string.
    """
    path = os.path.join(setup_dir, *path_elements)
    for line in open(path):
        for match in re.finditer('__version__\s*=\s(.*)$', line):
            return ast.literal_eval(match.group(1))
    raise RuntimeError("version string not found in {0}".format(path))


setup(
        name='boofuzz',
        version=find_version("boofuzz", "__init__.py"),
        maintainer='Joshua Pereyda',
        maintainer_email='joshua.t.pereyda@gmail.com',
        url='https://github.com/jtpereyda/boofuzz',
        license='GPL',
        packages=find_packages(exclude=['unit_tests', 'requests', 'examples', 'utils', 'web', 'new_examples']),
        package_data={'boofuzz': ['web/templates/*', 'web/static/css/*']},
        install_requires=[
            'future', 'pyserial', 'pydot', 'tornado==4.0.2',
            'Flask==0.10.1', 'impacket', 'colorama', 'attrs', 'click', 'psutil'],
        extras_require={
            # This list is duplicated in tox.ini. Make sure to change both!
            'dev': ['check-manifest', 'mock', 'pytest', 'pytest-bdd', 'netifaces', 'ipaddress'],
        },
        classifiers=[
            'Development Status :: 4 - Beta',
            'Environment :: Console',
            'Intended Audience :: Developers',
            'Intended Audience :: Science/Research',
            'License :: OSI Approved :: MIT License',
            'Natural Language :: English',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.7',
            'Topic :: Security',
            'Topic :: Software Development :: Testing :: Traffic Generation',
        ]
)
