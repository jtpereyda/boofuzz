#!/usr/bin/env python
import ast
import os
import re
import sys
from io import open

from setuptools import find_packages, setup

setup_dir = os.path.abspath(os.path.dirname(__file__))


def find_version(*path_elements):
    """Search a file for `__version__ = 'version number'` and return version.

    @param path_elements: Arguments specifying file to search.

    @return: Version number string.
    """
    path = os.path.join(setup_dir, *path_elements)
    for line in open(path):
        for match in re.finditer(r"__version__\s*=\s(.*)$", line):
            return ast.literal_eval(match.group(1))
    raise RuntimeError("version string not found in {0}".format(path))


def get_long_description():
    descr = []
    for fname in "README.rst", "CHANGELOG.rst":
        with open(os.path.join(setup_dir, fname), encoding="utf-8") as f:
            descr.append(f.read())
    return "\n\n".join(descr)


extra_requirements = {
    "dev": [
        "tox",
        "flake8",
        "check-manifest",
        "mock",
        "pytest",
        "pytest-bdd",
        "pytest-cov",
        "netifaces",
        "ipaddress",
        "wheel",
    ],
    "docs": ["sphinx", "sphinx_rtd_theme", "pygments>=2.4.0"],
}
extra_requirements["dev"] += extra_requirements["docs"]

if sys.version_info >= (3, 6):
    extra_requirements["dev"] += ["black"]


setup(
    name="boofuzz",
    version=find_version("boofuzz", "__init__.py"),
    description="A fork and successor of the Sulley Fuzzing Framework",
    long_description=get_long_description(),
    long_description_content_type="text/x-rst",
    maintainer="Joshua Pereyda",
    maintainer_email="joshua.t.pereyda@gmail.com",
    url="https://github.com/jtpereyda/boofuzz",
    packages=find_packages(exclude=["docs", "examples", "request_definitions", "unit_tests", "utils"]),
    package_data={"boofuzz.web": ["static/*", "static/*/*", "templates/*", "templates/*/*"]},
    install_requires=[
        "attrs",
        "backports.shutil_get_terminal_size",
        "click",
        "colorama",
        "Flask",
        "funcy",
        "future",
        "impacket",
        "psutil",
        "pyserial",
        "pydot",
        "six",
        "tornado~=5.0",
    ],
    extras_require=extra_requirements,
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
    entry_points={"console_scripts": ["boo=boofuzz.cli:main"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Console :: Curses",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Testing :: Traffic Generation",
    ],
)
