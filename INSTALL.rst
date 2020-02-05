Installing boofuzz
==================

Prerequisites
-------------

Boofuzz requires Python 2.7 or ≥3.5. Recommended installation requires ``pip``.
To ensure forward compatibility, python 3 is recommended. As a base
requirement, the following packages are needed:

Ubuntu/Debian
  ``sudo apt-get install python3-pip python3-venv``
OpenSuse
  ``sudo zypper install python3-pip python3-virtualenv``
CentOS
  ``sudo yum install python36 python3-pip``


Install
-------
It is strongly recommended to set up boofuzz in a `virtual environment
(virtualenv) <https://docs.python.org/3/tutorial/venv.html>`_. First, create a
directory that will hold our boofuzz install:

::

    $ mkdir boofuzz && cd boofuzz
    $ python3 -m venv env

This creates a new virtual environment env in the current folder. Note that the
python version in a virtual environment is fixed and chosen at its creation.
Unlike global installs, within a virtual environment ``python`` is aliased to
the python version of the virtual environment.

Next, activate the virtual environment:

::

    $ source env/bin/activate

Or, if you are on Windows:

::

    $ env\Scripts\activate.bat

Ensure you have the latest version of both ``pip`` and ``setuptools``:

::

    (env) $ pip install -U pip setuptools

Finally, install boofuzz:

::

    (env) $ pip install boofuzz

To run and test your fuzzing scripts, make sure to always activate the virtual
environment beforehand.

From Source
-----------


1. Like above, it is recommended to set up a virtual environment. Depending on your
   concrete setup, this is largely equivalent to the steps outlined above. Make sure
   to upgrade ``setuptools`` and ``pip``.
2. Download the source code. You can either grab a zip from https://github.com/jtpereyda/boofuzz
   or directly clone it with git:
   ::

      $ git clone https://github.com/jtpereyda/boofuzz.git

3. Install. Run ``pip`` from within the boofuzz directory after activating the virtual
   environment:
   ::

       pip install .

Tips:

-  Use the ``-e`` option for developer mode, which allows changes to be
   seen automatically without reinstalling:

   ::

       pip install -e .

-  To install developer tools (unit test dependencies, test runners, etc.) as well:

   ::

       pip install -e .[dev]

   Note that ``black`` needs python ≥3.6.

-  If you’re behind a proxy:

   ::

       set HTTPS_PROXY=http://your.proxy.com:port

- If you're planning on developing boofuzz itself, you can save a directory and
  create your virtual environment after you've cloned the source code (so ``env/``
  is within the main boofuzz directory).

Extras
------

process\_monitor.py (Windows only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
   Currently, the process monitor is python2 only due to a dependency on
   ``pydbg``. See the discussion in `Issue #370
   <https://github.com/jtpereyda/boofuzz/issues/370#issuecomment-578423069>`_
   for more information regarding python 3 support.

   As always, contributions are welcome!

The process monitor is a tool for detecting crashes and restarting an
application on Windows (process\_monitor\_unix.py is provided for Unix).

The process monitor is included with boofuzz, but requires additional
libraries to run. While boofuzz typically runs on a different machine
than the target, the process monitor must run on the target machine
itself.

If you want to use process\_monitor.py, follow these additional steps:

1. Download and install pydbg.

   1. Make sure to install and run pydbg using a 32-bit Python 2 interpreter, not 64-bit!
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
