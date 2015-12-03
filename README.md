boofuzz
=======
Boofuzz is a fork of and the successor to the [Sulley](https://github.com/OpenRCE/sulley) fuzzing framework.
Besides numerous bug fixes, boofuzz aims for extensibility, with the eventual goal of being able to fuzz literally anything.

Why?
----
Sulley has been the preeminent open source fuzzer for sometime, but has fallen out of maintenance.

Features
--------
Like Sulley, boofuzz incorporates all the critical elements of a fuzzer:

 - Easy and quick data generation.
 - Instrumentation, AKA failure detection.
 - Target reset after failure.
 - Recording of test data.

Unlike Sulley, boofuzz also features:

 - Much easier install experience!
 - Support for arbitrary communications mediums.
 - _Extensible_ instrumentation/failure detection.
 - Better recording of test data.
 - Far fewer bugs.
 
Sulley is affectionately named after the creature from Monsters Inc., because of his fuzziness.
Boofuzz is likewise named after the only creature known to have scared Sulley himself, boo!

![Boo from Monsters Inc](http://s21.postimg.org/rssnxdho7/boo_happy.png)

Prerequisites
-------------
Boofuzz requires Python. Recommended installation requires `pip`.

Ubuntu: `sudo apt-get install python-pip`

Windows: See this [help site](http://www.howtogeek.com/197947/how-to-install-python-on-windows/)
but make sure to get Python 2.x instead of 3.x (pip is included).

Installation
------------

1. Download source code: [https://github.com/jtpereyda/boofuzz]()
2. Install. Run `pip` from within the boofuzz directory:
    * Ubuntu: `sudo pip install .`
    * Windows: `pip install .`

Tips:

 * Use the `-e` option for developer mode, which allows changes to be seen
   automatically without reinstalling:

        `sudo pip -e install boofuzz`

* Behind proxy:

        `set HTTPS_PROXY=http://your.proxy.com:port`
    * On Linux, also use `sudo`'s `-E` option:

        `sudo -E pip -e install boofuzz`

Extras
------

### process_monitor.py (Windows only)
The process monitor is a tool for detecting crashes and restarting an
application on Windows (process_monitor_unx.py is provided for Unix).

The process monitor is included with boofuzz, but requires additional libraries
to run. While boofuzz typically runs on a different machine than the target,
the process monitor must run on the target machine itself.

If you want to use process_monitor.py, follow these additional steps:

1. Download and install pydbg.
    1. The OpenRCE repository doesn't have a setup.py. Use Fitblip's [fork](https://github.com/Fitblip/pydbg).
    2. `C:\Users\IEUser\Downloads\pydbg-master>pip install ./pydbg-master`
2. Download and install [pydasm](https://github.com/jtpereyda/libdasm).
    1. `C:\Users\IEUser\Downloads\libdasm-master\libdasm-master\pydasm>python setup.py build_ext`**
    2. `C:\Users\IEUser\Downloads\libdasm-master\libdasm-master\pydasm>python setup.py install`
3. Verify that process_monitor.py runs:

        C:\Users\IEUser\Downloads\boofuzz>python process_monitor.py
        ERR> USAGE: process_monitor.py
            [-c|--crash_bin FILENAME] filename to serialize crash bin class to
            [-p|--proc_name NAME]     process name to search for and attach to
            [-i|--ignore_pid PID]     PID to ignore when searching for target process
            [-l|--log_level LEVEL]    log level: default 1, increase for more verbosity
            [--port PORT]             TCP port to bind this agent to


        C:\Users\IEUser\Downloads\boofuzz>

** Building pydasm on Windows requires the [Visual C++ Compiler for Python 2.7](http://aka.ms/vcpython27).

### Deprecated: network_monitor.py
The network monitor was Sulley's primary tool for recording test data, and has
been replaced with boofuzz's logging capabilities. If you want to use it, you
must first install the appropriate pcap libraries.

#### Ubuntu

1. `sudo apt-get install python-dev libpcap-dev`
2. `pip install pcapy`

#### Windows

1. Get the Visual C++ Compiler for Python 2.7 [here](http://aka.ms/vcpython27).
2. Download and install the latest [WinPcap](http://www.dependencywalker.com/).
3. Download and extract the latest [WinPcap developer pack](https://www.winpcap.org/devel.htm).
4. Use `pip` to install pcapy, with options to include the WinPcap Lib and Include folders.

        `pip install pcapy --global-option=build_ext --global-option="-LC:\Users\IEUser\Downloads\WpdPack_4_1_2\WpdPack\Lib" --global-option="-IC:\Users\IEUser\Downloads\WpdPack_4_1_2\WpdPack\Include"`
5. Verify network_monitor.py runs:

        C:\Users\IEUser\Desktop\boofuzz>python network_monitor.py
        ERR> USAGE: network_monitor.py
            <-d|--device DEVICE #>    device to sniff on (see list below)
            [-f|--filter PCAP FILTER] BPF filter string
            [-P|--log_path PATH]      log directory to store pcaps to
            [-l|--log_level LEVEL]    log level (default 1), increase for more verbosity
            [--port PORT]             TCP port to bind this agent to

        Network Device List:
            [0] {0031B01C-6A4B-4CBB-8596-6B6DE742E7FC}  192.168.118.133


        C:\Users\IEUser\Desktop\boofuzz>

Getting Started
---------------
No quickstart guide is available yet, but in the mean time you can use this [Sulley FTP example](https://www.securepla.net/fuzzing-101-with-sulley/) as a baseline.

Contributions
-------------
Pull requests are welcome, as boofuz is actively maintained (at the time of this writing ;)).

Support
-------
If your question takes the form of "How do I... with boofuzz?" or "I got this error with boofuzz, why?", consider posting your question on Stack Overflow. Make sure to use the `fuzzing` tag.

If you've found a bug, or have an idea/suggestion/request, file an issue here on GitHub.

For other questions, feel free to [email me](https://github.com/jtpereyda).
