boofuzz: Network Protocol Fuzzing for Humans
============================================

.. image:: https://github.com/jtpereyda/boofuzz/workflows/Test/badge.svg?branch=master
    :target: https://github.com/jtpereyda/boofuzz/actions?query=workflow%3ATest+branch%3Amaster
.. image:: https://readthedocs.org/projects/boofuzz/badge/?version=latest
    :target: https://boofuzz.readthedocs.io/
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/boofuzz.svg
    :target: https://pypi.org/project/boofuzz/
.. image:: https://badges.gitter.im/jtpereyda/boofuzz.svg
    :alt: Join the chat at https://gitter.im/jtpereyda/boofuzz
    :target: https://gitter.im/jtpereyda/boofuzz
.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

Boofuzz is a fork of and the successor to the venerable `Sulley`_ fuzzing
framework. Besides numerous bug fixes, boofuzz aims for extensibility.
The goal: fuzz everything.

Why?
----

Sulley has been the preeminent open source fuzzer for some time, but has
fallen out of maintenance.

Features
--------

Like Sulley, boofuzz incorporates all the critical elements of a fuzzer:

-  Easy and quick data generation.
-  Instrumentation – AKA failure detection.
-  Target reset after failure.
-  Recording of test data.

Unlike Sulley, boofuzz also features:

-  Much easier install experience!
-  Support for arbitrary communications mediums.
-  Built-in support for serial fuzzing, ethernet- and IP-layer, UDP broadcast.
-  Better recording of test data -- consistent, thorough, clear.
-  Test result CSV export.
-  *Extensible* instrumentation/failure detection.
-  Far fewer bugs.

Sulley is affectionately named after the giant teal and purple creature
from Monsters Inc. due to his fuzziness. Boofuzz is likewise named after
the only creature known to have scared Sulley himself: Boo!

.. figure:: https://github.com/jtpereyda/boofuzz/raw/master/_static/boo.png
   :alt: Boo from Monsters Inc

   Boo from Monsters Inc

Installation
------------
::

    pip install boofuzz


Boofuzz installs as a Python library used to build fuzzer scripts. See
:ref:`install` for advanced and detailed instructions.


.. toctree::
    :caption: User Guide
    :maxdepth: 2

    user/install
    user/quickstart
    user/contributing


Public Protocol Libraries
-------------------------

The following protocol libraries are free and open source, but the implementations are not at all close to full protocol
coverage:

- `boofuzz-ftp`_
- `boofuzz-http`_

If you have an open source boofuzz protocol suite to share, please :ref:`let us know <community>`!

.. toctree::
    :caption: API Documentation
    :maxdepth: 2

    source/Session
    source/Target
    user/connections
    user/monitors
    user/logging
    user/protocol-definition
    user/static-protocol-definition
    user/other-modules

.. toctree::
    :maxdepth: 1

    user/changelog

Contributions
-------------

Pull requests are welcome, as boofuzz is actively maintained (at the
time of this writing ;)). See :ref:`contributing`.

.. _community:

Community
---------

For questions that take the form of “How do I… with boofuzz?” or “I got
this error with boofuzz, why?”, consider posting your question on Stack
Overflow. Make sure to use the ``fuzzing`` tag.

If you’ve found a bug, or have an idea/suggestion/request, file an issue
here on GitHub.

For other questions, check out boofuzz on `gitter`_ or `Google Groups`_.

For updates, follow `@b00fuzz`_ on Twitter.

.. _Sulley: https://github.com/OpenRCE/sulley
.. _Google Groups: https://groups.google.com/d/forum/boofuzz
.. _gitter: https://gitter.im/jtpereyda/boofuzz
.. _@b00fuzz: https://twitter.com/b00fuzz
.. _boofuzz-ftp: https://github.com/jtpereyda/boofuzz-ftp
.. _boofuzz-http: https://github.com/jtpereyda/boofuzz-http


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
