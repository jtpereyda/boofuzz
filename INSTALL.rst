Installing boofuzz
==================

Prerequisites
-------------

Boofuzz requires Python ≥ 3.5. Recommended installation requires ``pip``. As a base requirement, the following packages
are needed:

Ubuntu/Debian
  ``sudo apt-get install python3-pip python3-venv build-essential``
OpenSuse
  ``sudo zypper install python3-devel gcc``
CentOS
  ``sudo yum install python3-devel gcc``

Install
-------
It is strongly recommended to set up boofuzz in a `virtual environment
(venv) <https://docs.python.org/3/tutorial/venv.html>`_. First, create a directory that will hold our boofuzz install:

.. code-block:: bash

    $ mkdir boofuzz && cd boofuzz
    $ python3 -m venv env

This creates a new virtual environment env in the current folder. Note that the
Python version in a virtual environment is fixed and chosen at its creation.
Unlike global installs, within a virtual environment ``python`` is aliased to
the Python version of the virtual environment.

Next, activate the virtual environment:

.. code-block:: bash

    $ source env/bin/activate

Or, if you are on Windows:

.. code-block:: batch

    > env\Scripts\activate.bat

Ensure you have the latest version of both ``pip`` and ``setuptools``:

.. code-block:: bash

    (env) $ pip install -U pip setuptools

Finally, install boofuzz:

.. code-block:: bash

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

   .. code-block:: bash

      $ git clone https://github.com/jtpereyda/boofuzz.git

3. Install. Run ``pip`` from within the boofuzz directory after activating the virtual
   environment:

   .. code-block:: bash

       $ pip install .

Tips:

-  Use the ``-e`` option for developer mode, which allows changes to be
   seen automatically without reinstalling:

   .. code-block:: bash

       $ pip install -e .

-  To install developer tools (unit test dependencies, test runners, etc.) as well:

   .. code-block:: bash

       $ pip install -e .[dev]

   Note that `black <https://github.com/psf/black>`_ needs Python ≥ 3.6.

-  If you’re behind a proxy:

   .. code-block:: bash

       $ set HTTPS_PROXY=http://your.proxy.com:port

- If you're planning on developing boofuzz itself, you can save a directory and
  create your virtual environment after you've cloned the source code (so ``env/``
  is within the main boofuzz directory).

Extras
------

process\_monitor.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The process monitor is a tool for detecting crashes and restarting an application on Windows or Linux. While boofuzz
typically runs on a different machine than the target, the process monitor must run on the target machine itself.

network\_monitor.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The network monitor was Sulley’s primary tool for recording test data,
and has been replaced with boofuzz’s logging mechanisms.
However, some people still prefer the PCAP approach.

.. note::
    The network monitor requires Pcapy and Impacket, which will not be automatically installed with boofuzz. You can
    manually install them with ``pip install pcapy impacket``.

    If you run into errors, check out the Pcapy requirements on the `project page <https://github.com/helpsystems/pcapy>`_.

.. _help site: http://www.howtogeek.com/197947/how-to-install-python-on-windows/
.. _releases page: https://github.com/jtpereyda/boofuzz/releases
.. _`https://github.com/jtpereyda/boofuzz`: https://github.com/jtpereyda/boofuzz
