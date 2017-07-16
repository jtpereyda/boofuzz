boofuzz: Network Protocol Fuzzing for Humans
============================================

.. image:: https://travis-ci.org/jtpereyda/boofuzz.svg?branch=master
    :target: https://travis-ci.org/jtpereyda/boofuzz
.. image:: https://readthedocs.org/projects/boofuzz/badge/?version=latest
    :target: http://boofuzz.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/boofuzz.svg
    :target: https://pypi.python.org/pypi/boofuzz
.. image:: https://badges.gitter.im/jtpereyda/boofuzz.svg
    :alt: Join the chat at https://gitter.im/jtpereyda/boofuzz
    :target: https://gitter.im/jtpereyda/boofuzz?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

Boofuzz is a fork of and the successor to the venerable `Sulley`_ fuzzing
framework. Besides numerous bug fixes, boofuzz aims for extensibility,
with the eventual goal of being able to fuzz anything fuzzable.

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

.. figure:: _static/boo.png
   :alt: Boo from Monsters Inc

   Boo from Monsters Inc

Installation
------------
::

    pip install boofuzz


Boofuzz installs as a Python library used to build fuzzer scripts. See
`INSTALL.rst`_ for advanced and detailed instructions.

Getting Started
---------------

No quickstart guide is available yet, but in the meantime you can use
this `Sulley FTP example`_ as a baseline.

Contributions
-------------

Pull requests are welcome, as boofuzz is actively maintained (at the
time of this writing ;)).

Support
-------

If your question takes the form of “How do I… with boofuzz?” or “I got
this error with boofuzz, why?”, consider posting your question on Stack
Overflow. Make sure to use the ``fuzzing`` tag.

If you’ve found a bug, or have an idea/suggestion/request, file an issue
here on GitHub.

For other questions, check out boofuzz on `gitter`_ or `Google Groups`_.

For updates, follow `@fuzztheplanet`_ on Twitter.

.. _Sulley: https://github.com/OpenRCE/sulley
.. _INSTALL.rst: INSTALL.rst
.. _Sulley FTP example: https://www.securepla.net/fuzzing-101-with-sulley/
.. _Google Groups: https://groups.google.com/d/forum/boofuzz
.. _gitter: https://gitter.im/jtpereyda/boofuzz
.. _@fuzztheplanet: https://twitter.com/fuzztheplanet
