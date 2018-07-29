Installing boofuzz
==================

Prerequisites
-------------

Boofuzz requires Python. Recommended installation requires ``pip``.

Ubuntu: ``sudo apt-get install python-pip``

Windows: See this `help site`_ but make sure to get Python 2.x instead
of 3.x (pip is included).

Install
-------
::

    pip install boofuzz

From Source
-----------

1. Download source code: `https://github.com/jtpereyda/boofuzz`_
2. Install. Run ``pip`` from within the boofuzz directory:

   -  Ubuntu: ``sudo pip install .``
   -  Windows: ``pip install .``

Tips:

-  Use the ``-e`` option for developer mode, which allows changes to be
   seen automatically without reinstalling:

   ::

       `sudo pip install -e .`

-  To install developer tools (unit test dependencies, test runners, etc.) as well:

   ::

       `sudo pip install -e .[dev]`

-  If you’re behind a proxy:

   ::

       `set HTTPS_PROXY=http://your.proxy.com:port`

   -  On Linux, also use ``sudo``\ ’s ``-E`` option:

      ``sudo -E pip install -e .``

Extras
------

process\_monitor.py (Windows only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The process monitor is a tool for detecting crashes and restarting an
application on Windows (process\_monitor\_unix.py is provided for Unix).

The process monitor is included with boofuzz, but requires additional
libraries to run. While boofuzz typically runs on a different machine
than the target, the process monitor must run on the target machine
itself.

If you want to use process\_monitor.py, follow these additional steps:

1. Download and install pydbg.

   1. Make sure to install and run pydbg using a 32-bit Python interpreter, not 64-bit!
   2. The OpenRCE repository doesn’t have a setup.py. Use Fitblip’s
      `fork`_.
   3. ``C:\Users\IEUser\Downloads\pydbg>pip install .``

2. Download and install `pydasm`_.

   1. ``C:\Users\IEUser\Downloads\libdasm\pydasm>python setup.py build_ext``\ \*\*
   2. ``C:\Users\IEUser\Downloads\libdasm\pydasm>python setup.py install``

3. Verify that process\_monitor.py runs:

    ::

        C:\Users\IEUser\Downloads\boofuzz>python process_monitor.py -h
        usage: procmon [-h] [--debug] [--quiet] [-f STR] [-c FILENAME] [-i PID]
                       [-l LEVEL] [-p NAME] [-P PORT]

        optional arguments:
          -h, --help            show this help message and exit
          --debug               toggle debug output
          --quiet               suppress all output
          -f STR, --foo STR     the notorious foo option
          -c FILENAME, --crash_bin FILENAME
                                filename to serialize crash bin class to
          -i PID, --ignore_pid PID
                                PID to ignore when searching for target process
          -l LEVEL, --log_level LEVEL
                                log level: default 1, increase for more verbosity
          -p NAME, --proc_name NAME
                                process name to search for and attach to
          -P PORT, --port PORT  TCP port to bind this agent to

\*\* Building pydasm on Windows requires the `Visual C++ Compiler for
Python 2.7`_.

Deprecated: network\_monitor.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The network monitor was Sulley’s primary tool for recording test data,
and has been replaced with boofuzz’s logging mechanisms.
However, some people still prefer the PCAP approach.

.. _help site: http://www.howtogeek.com/197947/how-to-install-python-on-windows/
.. _releases page: https://github.com/jtpereyda/boofuzz/releases
.. _`https://github.com/jtpereyda/boofuzz`: https://github.com/jtpereyda/boofuzz
.. _fork: https://github.com/Fitblip/pydbg
.. _pydasm: https://github.com/jtpereyda/libdasm
.. _Visual C++ Compiler for Python 2.7: http://aka.ms/vcpython27
