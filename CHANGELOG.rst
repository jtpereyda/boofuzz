Changelog
=========

v0.3.0
------
Features
^^^^^^^^
- Memory optimization: Efficient mutation generation and smarter string reuse -- decrease memory consumption by orders of magnitude.
- `Aligned` block: Aligns content length to multiple of certain number of bytes.
- Relative names: Name references for `Checksum`, `Size`, etc. now resolve absolute and relative names. Block and primitive
  names no longer need to be globally unique within a message, they only need to be locally unique within a block.
- Passing data between messages: Callbacks now have a `TestCaseContext` object to which one can save data to be used
  later in the test case. `TestCaseSessionReference` can be passed as a default value in a protocol definition. The name
  it references must have been saved by the time that message in the protocol is reached.
- `Fuzzable` rewrite: Simpler definitions for new fuzz primitives. See `static.py` for an example of a very simple primitive.
- Protocol definition: Protocols can now be defined with an object oriented rather than static approach.
- Independent mutation and encoding steps: Will enable multiple mutations and code coverage feedback.
- Procmon: Additional debug steps. Partial backwards compatibility for old interface.
- `ProcessMonitorLocal` allows running procmon as part of fuzzer process.
- Network monitor: improved network interface discovery (Linux support).
- Added support for fuzzing Unix sockets with the `UnixSocketConnection` class.
- Added metadata to ProtocolSession to support callbacks -- `current_message`, `previous_message`.
- All primitive arguments are now optional keyword arguments.

Fixes
^^^^^
- Various web interface fixes.
- Various refactors and simplifications.
- Fewer duplicates from `Group` primitives.
- Network monitor: fixed data_bytes calculation and PcapThread synchronization.
- Fixed a crash when using the network monitor.
- Session can now be "quiet" by passing an empty list of loggers.
- Process Monitor: fixed Thread.isAlive for Python 3.9 compatibility.
- Correctly truncate values of the string primitive when max_len or size is set.
- The string primitive will no longer generate duplicates when max_len or size is set.
- Greatly improved string to bytes conversion speed.

v0.2.1
------
Features
^^^^^^^^
- Added simple TFTP fuzzer example.

Fixes
^^^^^
- Fixed UDPSocketConnection data truncation when sending more data than the socket supports.
- Fixed execution of procmon stop_commands.
- Fixed TCP and SSL server connections.

v0.2.0
------
Features
^^^^^^^^
- Rewrote and split the SocketConnection class into individual classes per socket type.
- `SocketConnection` is now deprecated. Use the classes derived from `BaseSocketConnection` instead.
- Added support for receiving on raw Layer 2 and Layer 3 connections.
- Layer 2 and Layer 3 connections may now use arbitrary payload / MTU sizes.
- Moved connection related modules into new `connections` submodule.
- Added the ability to repeat sending of packages within a given time or count.
- Added optional timeout and threshold to quit infinite connection retries.
- Reworked Monitors, consolidated interface. Breaking change: session no longer has netmon_options and procmon_options.
- `SessionInfo` has had attributes renamed; procmon_results and netmon_results are deprecated and now aliases for monitor_results and monitor_data respectively.
- New `BoofuzzFailure` exception type allows callback methods to signal a failure that should halt the current test case.
- Added `capture_output` option to process monitor to capture target process stderr/stdout .
- Added post-start-target callbacks (called every time a target is started or restarted).
- Added method to gracefully stop PED-RPC Server.
- Added new boofuzz logo and favicon to docs and webinterface.
- Added `FileConnection` to dump messages to files.
- Removed deprecated session arguments `fuzz_data_logger`, `log_level`, `logfile`, `logfile_level` and `log()`.
- Removed deprecated logger `FuzzLoggerFile`.
- `crc32c` is no longer a required package. Install manually if needed.

Fixes
^^^^^
- Fixed size of s_size block when output is ascii.
- Fixed issue with tornado on Python 3.8 and Windows.
- Fixed various potential type errors.
- Renamed `requests` folder to `request_definitions` because it shadowed the name of the `requests` python module.
- Examples are up to date with current Boofuzz version.
- Modified timings on serial_connection unit tests to improve test reliability.
- Refactored old unit-tests.
- Fixed network monitor compatibility with Python 3.
- Minor console GUI optimizations.
- Fixed crash_threshold_element handling if blocks are used.
- Fixed many bugs in which a failure would not stop the test case evaluation.

v0.1.6
------
Features
^^^^^^^^
- New primitive `s_bytes` which fuzzes an arbitrary length binary value (similiar to `s_string`).
- We are now using `Black` for code style standardization.
- Compatibility for Python 3.8
- Added crc32c as checksum algorithm (Castagnoli).
- Added favicon for web interface.
- Pushed Tornado to 5.x and unpinned Flask.

Fixes
^^^^^
- Test cases were not being properly closed when using the check_message() functionality.
- Some code style changes to meet PEP8.
- `s_group` primitive was not accepting empty default value.
- Timeout during opening TCP connection now raises BoofuzzTargetConnectionFailedError exception.
- SSL/TLS works again. See `examples/fuzz-ssl-server.py` and `examples/fuzz-ssl-client.py`.
- Dropped six.binary_type in favor of b"" format.
- Fixed process monitor handling of backslashes in Windows start commands.
- Fixed and documented `boo open`.
- Fixed receive function in `fuzz_logger_curses`.
- Installing boofuzz with `sudo` is no longer recommended, use the `--user` option of pip instead.
- Fixed setting socket timeout options on Windows.
- If all sockets are exhausted, repeatedly try fuzzing for 4 minutes before failing.
- Fixed CSV logger send and receive data decoding.
- Handle SSL-related exception. Added `ignore_connection_ssl_errors` session attribute that can
  be set to True to ignore SSL-related error on a test case.
- Fixed `s_from_file` decoding in Python 2 (the encoding parameter is now depreciated).
- Updated documentation of `s_checksum`. It is possible to use a custom algorithm with this block.

v0.1.5
------
Features
^^^^^^^^
- New curses logger class to provide a console gui similar to the webinterface. Use the session option `console_gui` to enable it.
  This has not been tested under Windows!
- Compatibility for Python 3
- Large test cases are now truncated, unless a failure is detected.
- When a target fails to respond after restart, boofuzz will now continue to restart instead of crashing.
- New Session option `keep_web_open` to allow analyzing the test results after test completion.
- Process monitor creates new crash file for each run by default.
- Long lines now wrap in web view; longer lines no longer need to be truncated.
- Process monitor now stores crash bins in JSON format instead of pickled format.
- Process monitor in Windows will use `taskkill -F` if `taskkill` fails.

Fixes
^^^^^
- Web server no longer crashes when asked for a non-existing test case.
- EINPROGRESS socket error is now handled while opening a socket (note: this sometimes-transient error motivated the move to retry upon connection failure)

v0.1.4
------
Features
^^^^^^^^
- New Session options `restart_callbacks`, `pre_send_callbacks`, and `post_test_case_callbacks` to hand over custom callback functions.
- New Session option `fuzz_db_keep_only_n_pass_cases`. This allowes saving only n test cases preceding a failure or error to the database.
- Added logic to find next available port for web interface or disable the web interface.
- Removed sleep logs when sleep time is zero.
- Added option to reuse the connection to the target.

Fixes
^^^^^
- Windows process monitor now handles combination of proc_name and/or start_commands more reasonably
- Windows process monitor handles certain errors more gracefully
- Fixed target close behavior so post send callbacks can use the target.
- Fixed a dependency issue in installation.


v0.1.3
------
Features
^^^^^^^^
- Socket Connections now allow client fuzzing.
- Log only the data actually sent, when sending is truncated. Helps reduce database size, especially when fuzzing layer 2 or 3.
- `Target` `recv` function now accepts a `max_recv_bytes` argument.

Fixes
^^^^^
- Fixed install package -- now includes JavaScript files.

v0.1.2
------
Features
^^^^^^^^
- Clearer error message when procmon is unavailable at fuzz start.
- Web UI now refreshes current case even when snap-to-current-test-case is disabled.

Fixes
^^^^^
- Web UI no longer permits negative test cases.
- Fix Windows procmon regression.
- Minor fixes and UI tweaks.

v0.1.1
------
Features
^^^^^^^^
- New `boo open` command can open and inspect saved database log files.
- Unix procmon now saves coredumps by default.
- Improved "Cannot connect to target" error message.
- Improved API for registering callbacks.
- Made the global `REQUESTS` map available in top level boofuzz package.

Fixes
^^^^^
- Handle exceptions when opening crash bin files in process monitor.
- Fix Block.__len__ to account for custom encoder.

v0.1.0
------
Features
^^^^^^^^
- Web UI
    - Statistics now auto-update.
    - Test case logs now stream on the main page.
    - Cool left & right arrow buttons to move through test case
- New ``Session`` parameter ``receive_data_after_fuzz``. Controls whether to execute a receive step after sending
  fuzz messages. Defaults to False. This significantly speeds up tests in which the target tends not to respond to
  invalid messages.

Fixes
^^^^^
- Text log output would include double titles, e.g. "Test Step: Test Step: ..."

v0.0.13
-------
Features
^^^^^^^^
- Web UI
    - Test case numbers are now clickable and link to test case detail view.
    - Test case details now in color!
- ``FuzzLoggerDB``
    - Added FuzzLoggerDB to allow querying of test results during and after test run. Saves results in a SQLite file.
    - Added ``Session.open_test_run()`` to read test results database from previous test run.
- New ``Session.feature_check()`` method to verify protocol functionality before fuzzing.
- Process Monitor
    - Unify process monitor command line interface between Unix and Windows.
    - Added procmon option ``proc_name`` to support asynchronously started target processes.
    - procmon is now checked for errors before user ``post_send()`` is called, reducing redundant error messages.
    - Improved procmon logging.
    - Process monitor gives more helpful error messages when running 64-bit application (unsupported) or when a process is
      killed before being attached
- Logging Improvements
    - ``Target`` ``open()`` and ``close()`` operations are now logged.
    - Added some optional debug output from boofuzz runtime.
    - Improve capability and logging of messages' ``callback`` methods.
- New ``Session`` & Connection Options
    - Add ``Session`` ``receive_data_after_each_request`` option to enable disabling of data receipt after messages are sent.
    - ``Session`` ``skip`` argument replaced with ``index_start`` and ``index_end``.
    - ``Session`` now has separate crash thresholds for elements/blocks and nodes/messages.
    - Give ``SocketConnection`` separate timeouts for ``send()``/``recv()``.
- Ease of Use
    - ``Target.recv()`` now has a default ``max_bytes`` value.
    - Added ``DEFAULT_PROCMON_PORT`` constant.
    - ``Session.post_send()``'s ``sock`` parameter now deprecated (use ``target`` instead).


Fixes
^^^^^
- Fixed bug in which failures were not recognized.
- ``BitField`` blocks with ASCII format reported incorrect sizes.
- Fixed bug in ``s_update``.
- Handle socket errors that were getting missed.
- Fixed process monitor logging when providing more or less than 1 stop/start commands.
- Show graceful error on web requests for non-existent test cases.
- ``get_max_udp_size()`` was crashing in Windows.
- ``String`` padding was not always being applied.
- ``String`` was not accepting unicode strings in ``value`` parameter.
- ``String`` was skipping valid mutations and reporting wrong ``num_mutations()`` when ``size`` parameter was used.
- Unix and Windows process monitors now share much more code.

Development
^^^^^^^^^^^
- Added unit tests for ``BitField``.
- Cleaned up CSS on web pages.
- Added a unit test to verify restart on failure behavior

0.0.12
------
Features
^^^^^^^^
- Test cases now have descriptive names
- Added Session methods to fuzz a test cae by name: ``fuzz_by_name`` and ``fuzz_single_node_by_path``

Fixes
^^^^^
- Fixed test case numbers when using ``fuzz_single_case``

0.0.11
------
Features
^^^^^^^^
-  Set Session ``check_data_received_each_request`` to False to disable receive after send.

Fixes
^^^^^
-  Dosctring format fixes.

0.0.10
------
Features
^^^^^^^^
-  Add Session ignore_connection_reset parameter to suppress ECONNRESET errors.
-  Add Session ignore_connection_aborted parameter to suppress ECONNABORTED errors.

Fixes
^^^^^
-  Fix Session class docstring formats.

0.0.9
-----
Features
^^^^^^^^
-  ``s_size`` is now fuzzable by default.
-  Add new s_fuzz_list primitive to read fuzz value from files.
-  Add new FuzzLoggerCsv to write log in CSV format

Fixes
^^^^^
-  Fixed: Add missing dummy value for custom checksum, allowing recursive uses of length/checksum (issue #107)

0.0.8
-----
Features
^^^^^^^^
-  Console output - now with colors!
-  process_monitor_unix.py: added option to move coredumps for later analysis.
-  The process monitor (procmon) now tracks processes by PID by default rather than searching by name. Therefore,
   stop_commands and proc_name are no longer required.
-  SIGINT (AKA Ctrl+C) now works to close both boofuzz and process_monitor.py (usually).
-  Made Unix procmon more compatible with Windows.
-  Improved procmon debugger error handling, e.g., when running 64-bit apps.
-  Windows procmon now runs even if pydbg fails.
-  Added ``--help`` parameter to process monitor.
-  Target class now takes ``procmon`` and ``procmon_options`` in constructor.
-  Added example fuzz scripts.

Fixes
^^^^^
-  SIGINT (AKA Ctrl+C) now works to close both boofuzz and process_monitor.py (usually).
-  Fixed: The pedrpc module was not being properly included in imports.
-  Made process_monitor.py ``--crash_bin`` optional (as documented).
-  Improved procmon behavior when certain parameters aren't given.
-  Improved procmon error handling.
-  Fixed a bug in which the procmon would not properly restart a target that had failed without crashing.

0.0.7
-----
Features
^^^^^^^^
-  Added several command injection strings from fuzzdb.
-  Blocks can now be created and nested using ``with s_block("my-block"):``

Fixes
^^^^^
-  Fixed pydot import error message

0.0.6
-----
Features
^^^^^^^^
-  Added ``Request.original_value()`` function to render the request as if it were not fuzzed.
   This will help enable reuse of a fuzz definition to generate valid requests.
-  ``SocketConnection`` can now send and receive UDP broadcast packets using the ``udp_broadcast`` constructor
   parameter.
-  ``Target.recv()`` now logs an entry before receiving data, in order to help debug receiving issues.

Fixes
^^^^^
-  Maximum UDP payload value was incorrect, causing crashes for tests running over UDP. It now works on some systems,
   but the maximum value may be too high for systems that set it lower than the maximum possible value, 65507.
-  ``SocketConnection`` class now handles more send and receive errors:  ``ECONNABORTED``, ``ECONNRESET``,
   ``ENETRESET``, and ``ETIMEDOUT``.
-  Fixed setup.py to not include superfluous packages.

Development
^^^^^^^^^^^
-  Added two exceptions: ``BoofuzzTargetConnectionReset`` and ``BoofuzzTargetConnectionAborted``.
-  These two exceptions are handled in ``sessions.py`` and may be thrown by any ``ITargetConnection`` implementation.

0.0.5
-----
Fixes
^^^^^
-  Boofuzz now properly reports crashes detected by the process monitor. It was calling log_info instead of log_fail.
-  Boofuzz will no longer crash, but will rather give a helpful error message, if the target refuses socket connections.
-  Add utils/crash_binning.py to boofuzz/utils, avoiding import errors.
-  Fix procmon argument processing bug.
-  Fix typos in INSTALL.rst.

0.0.4
-----
-  Add Gitter badge to README.
-  Add default sleep_time and fuzz_data_logger for Session to simplify boilerplate.

0.0.3
-----
-  Fixed deployment from 0.0.2.
-  Simplify CONTRIBUTING.rst for automated deployment.
-  tox no longer runs entirely as sudo. The sudo has been moved into tox.ini and is more fine-grained.
-  Reduced default ``Session.__init__`` ``restart_sleep_time`` from 5 minutes to 5 seconds.

0.0.2
-----
Continuous deployment with Travis.

Development
^^^^^^^^^^^
-  Added build and PyPI badges.
-  Added CONTRIBUTING.rst.
-  check-manifest now runs in automated build.
-  Travis now deploys to PyPI!

0.0.1-dev5
----------
Development
^^^^^^^^^^^
-  Tests now run on tox.
-  Added Google Groups and Twitter link.

0.0.1-dev4
----------

Fixes
^^^^^
-  Missing property setters in ``boofuzz.request.Request`` now implemented.
-  Unit tests now pass on Windows.
-  Fixed wheel build issue; boofuzz subpackages were missing.

0.0.1-dev3
----------

Fixes
^^^^^
-  Session constructor param ``session_filename`` is now optional.

0.0.1-dev2
----------
New features
^^^^^^^^^^^^

-  Now on PyPI! ``pip install boofuzz``
-  API is now centralized so all classes are available at top level
   ``boofuzz.*``

   -  This makes it way easier to use. Everything can be used like
      ``boofuzz.MyClass`` instead of ``boofuzz.my_file.MyClass``.

-  Added ``EzOutletReset`` class to support restarting devices using an
   ezOutlet EZ-11b.

Backwards-incompatible
^^^^^^^^^^^^^^^^^^^^^^

-  Target now only takes an ``ITargetConnection``. This separates
   responsibilities and makes our code more flexible with different
   kinds of connections.

Fixes
^^^^^

-  Bugs fixed:

   -  ``helpers.udp_checksum`` was failing with oversized messages.
   -  Missing install requirements.
   -  Grammar and spelling.
   -  ``setup.py`` was previously installing around five mostly unwanted
      packages. Fixed.
   -  Removed deprecated unit tests.
   -  Removed overly broad exception handling in Session.
   -  ``Checksum.render()`` for UDP was not handling dependencies
      properly.

Back-end Improvements
^^^^^^^^^^^^^^^^^^^^^

This section took the most work. It has the least visible impact, but
all of the refactors enable new features, fixes, and unit tests.

-  Primitives and Blocks:

   -  Created ``IFuzzable`` which properly defines interface for
      ``Block``, ``Request``, and all ``BasePrimitive`` classes.
   -  Made effectively private members actually private.
   -  Eliminated ``exhaust()`` function. It was used only once and was
      primarily a convoluted break statement. Now it's gone. :)
   -  Split all block and primitive classes into separate files.

-  Many Unit tests added.

Other
^^^^^

-  Continuous integration with Travis is running!
-  Doc organization improvements.
-  Can now install with extras ``[dev]``

Initial Development Release - 0.0.1-dev1
----------------------------------------


-  Much easier install experience!
-  Support for arbitrary communications mediums.

   -  Added serial communications support.
   -  Improved sockets to fuzz at Ethernet and IP layers.

-  Extensible instrumentation/failure detection.
-  Better recording of test data.

   -  Records all sent and received data
   -  Records errors in human-readable format, in same place as
      sent/received data.

-  Improved functionality in checksum blocks.
-  Self-referential size and checksum blocks now work.
-  ``post_send`` callbacks can now check replies and log failures.
-  Far fewer bugs.
-  Numerous refactors within framework code.
