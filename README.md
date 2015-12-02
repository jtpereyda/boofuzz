boofuzz
=======
boofuzz is a fork of and the successor to the [Sulley](https://github.com/OpenRCE/sulley) fuzzing framework.
Besides numerous bug fixes, boofuzz aims for extensibility, with the eventual goal of being able to fuzz literally anything.

Why?
----
Sulley has been the preeminent open source fuzzer for sometime, but has fallen out of maintenance.

Features
--------
Like Sulley, boofuzz seeks to incorporate all the critical elements of a fuzzer:

 - Easy and quick data generation.
 - Instrumentation, AKA failure detection.
 - Target reset after failure.
 - Recording of test data.

Unlike Sulley, boofuzz also features:

 - Easier install experience!
 - Support for arbitrary communications mediums.
 - _Extensible_ instrumentation/failure detection.
 - Better recording of test data.
 
Sulley is affectionately named after the creature from Monsters Inc., because of his fuzziness.
Boofuzz is likewise named after the only creature known to have given Sulley himself a fright, boo!

![Boo from Monsters Inc](http://s21.postimg.org/rssnxdho7/boo_happy.png)

Installation
------------

### Linux/Unix
1. Make sure you have Python 2.7 installed, with `pip`.
    * `pip` on Ubuntu: `sudo apt-get install python-pip`
2. Install python-dev and pcap libraries.
    * Ubuntu: `sudo apt-get install python-dev libpcap-dev`
3. Download source code: `git clone https://github.com/jtpereyda/boofuzz.git`
4. Finally, use `pip` to install.
    * Regular: `sudo pip install boofuzz`
    * Developer mode (allows changes to be seen automatically without reinstalling): `sudo pip -e install boofuzz`
    * Behind proxy: `sudo -E pip -e install boofuzz`

### Windows

#### From Source

1. [Download and install](http://www.howtogeek.com/197947/how-to-install-python-on-windows/) Python for Windows (use 2.7.x instead of 3.x). `pip` should be included.
2. Get the Visual C++ Compiler for Python 2.7 [here](http://aka.ms/vcpython27).
3. Download and extract the latest [WinPcap developer pack](https://www.winpcap.org/devel.htm).
4. Download [boofuzz](https://github.com/jtpereyda/boofuzz) source code.
5. Use `pip` to install; use `pip` options to include the WinPcap Lib and Include folders.

        C:\Users\IEUser\Downloads\boofuzz-master\boofuzz-master>pip install . --global-option=build_ext --global-option="-LC:\Users\IEUser\Downloads\WpdPack_4_1_2\WpdPack\Lib" --global-option="-IC:\Users\IEUser\Downloads\WpdPack_4_1_2\WpdPack\Include"

    Use `-e` for developer/editable mode:

        C:\Users\IEUser\Downloads\boofuzz-master\boofuzz-master>pip install -e . --global-option=build_ext --global-option="-LC:\Users\IEUser\Downloads\WpdPack_4_1_2\WpdPack\Lib" --global-option="-IC:\Users\IEUser\Downloads\WpdPack_4_1_2\WpdPack\Include"

    If behind a proxy, set `HTTPS_PROXY` first:

        C:\Users\IEUser\Downloads\boofuzz-master\boofuzz-master>set HTTPS_PROXY=http://your.proxy.com:port

##### process_monitor.py (Windows only)
If you want to use process_monitor.py, follow these additional steps:

1. Download and install pydbg.
    - The OpenRCE repository doesn't have a setup.py. Use Fitblip's [fork](https://github.com/Fitblip/pydbg).
    - `C:\Users\IEUser\Downloads\pydbg-master>pip install ./pydbg-master`
2. Download and install [pydasm](https://github.com/jtpereyda/libdasm).
    - `C:\Users\IEUser\Downloads\libdasm-master\libdasm-master\pydasm>python setup.py build_ext`
    - `C:\Users\IEUser\Downloads\libdasm-master\libdasm-master\pydasm>python setup.py install`
3. Verify that process_monitor.py runs:

        C:\Users\IEUser\Downloads\boofuzz>python process_monitor.py
        ERR> USAGE: process_monitor.py
            <-c|--crash_bin FILENAME> filename to serialize crash bin class to
            [-p|--proc_name NAME]     process name to search for and attach to
            [-i|--ignore_pid PID]     ignore this PID when searching for the target process
            [-l|--log_level LEVEL]    log level (default 1), increase for more verbosity
            [--port PORT]             TCP port to bind this agent to


        C:\Users\IEUser\Downloads\boofuzz>

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
