0.0.12
======
Features
--------
- Test cases now have descriptive names
- Added Session methods to fuzz a test cae by name: `fuzz_by_name` and `fuzz_single_node_by_path`

Fixes
-----
- Fixed test case numbers when using `fuzz_single_case`

0.0.11
======
Features
--------
-  Set Session `check_data_received_each_request` to False to disable receive after send.

Fixes
-----
-  Dosctring format fixes.

0.0.10
======
Features
--------
-  Add Session ignore_connection_reset parameter to suppress ECONNRESET errors.
-  Add Session ignore_connection_aborted parameter to suppress ECONNABORTED errors.

Fixes
-----
-  Fix Session class docstring formats.

0.0.9
=====
Features
--------
-  `s_size` is now fuzzable by default.
-  Add new s_fuzz_list primitive to read fuzz value from files.
-  Add new FuzzLoggerCsv to write log in CSV format 

Fixes
-----
-  Fixed: Add missing dummy value for custom checksum, allowing recursive uses of length/checksum (issue #107)

0.0.8
=====
Features
--------
-  Console output - now with colors!
-  process_monitor_unix.py: added option to move coredumps for later analysis.
-  The process monitor (procmon) now tracks processes by PID by default rather than searching by name. Therefore,
   stop_commands and proc_name are no longer required.
-  SIGINT (AKA Ctrl+C) now works to close both boofuzz and process_monitor.py (usually).
-  Made Unix procmon more compatible with Windows.
-  Improved procmon debugger error handling, e.g., when running 64-bit apps.
-  Windows procmon now runs even if pydbg fails.
-  Added `--help` parameter to process monitor.
-  Target class now takes `procmon` and `procmon_options` in constructor.
-  Added example fuzz scripts.

Fixes
-----
-  SIGINT (AKA Ctrl+C) now works to close both boofuzz and process_monitor.py (usually).
-  Fixed: The pedrpc module was not being properly included in imports.
-  Made process_monitor.py `--crash_bin` optional (as documented).
-  Improved procmon behavior when certain parameters aren't given.
-  Improved procmon error handling.
-  Fixed a bug in which the procmon would not properly restart a target that had failed without crashing.

0.0.7
=====
Features
--------
-  Added several command injection strings from fuzzdb.
-  Blocks can now be created and nested using `with s_block("my-block"):`

Fixes
-----
-  Fixed pydot import error message

0.0.6
=====
Features
--------
-  Added ``Request.original_value()`` function to render the request as if it were not fuzzed.
   This will help enable reuse of a fuzz definition to generate valid requests.
-  ``SocketConnection`` can now send and receive UDP broadcast packets using the ``udp_broadcast`` constructor
   parameter.
-  ``Target.recv()`` now logs an entry before receiving data, in order to help debug receiving issues.

Fixes
-----
-  Maximum UDP payload value was incorrect, causing crashes for tests running over UDP. It now works on some systems,
   but the maximum value may be too high for systems that set it lower than the maximum possible value, 65507.
-  ``SocketConnection`` class now handles more send and receive errors:  ``ECONNABORTED``, ``ECONNRESET``,
   ``ENETRESET``, and ``ETIMEDOUT``.
-  Fixed setup.py to not include superfluous packages.

Development
-----------
-  Added two exceptions: ``BoofuzzTargetConnectionReset`` and ``BoofuzzTargetConnectionAborted``.
-  These two exceptions are handled in ``sessions.py`` and may be thrown by any ``ITargetConnection`` implementation.

0.0.5
=====
Fixes
-----
-  Boofuzz now properly reports crashes detected by the process monitor. It was calling log_info instead of log_fail.
-  Boofuzz will no longer crash, but will rather give a helpful error message, if the target refuses socket connections.
-  Add utils/crash_binning.py to boofuzz/utils, avoiding import errors.
-  Fix procmon argument processing bug.
-  Fix typos in INSTALL.rst.

0.0.4
=====
-  Add Gitter badge to README.
-  Add default sleep_time and fuzz_data_logger for Session to simplify boilerplate.

0.0.3
=====
-  Fixed deployment from 0.0.2.
-  Simplify CONTRIBUTING.rst for automated deployment.
-  tox no longer runs entirely as sudo. The sudo has been moved into tox.ini and is more fine-grained.
-  Reduced default ``Session.__init__`` ``restart_sleep_time`` from 5 minutes to 5 seconds.

0.0.2
=====
Continuous deployment with Travis.

Development
-----------
-  Added build and PyPI badges.
-  Added CONTRIBUTING.rst.
-  check-manifest now runs in automated build.
-  Travis now deploys to PyPI!

0.0.1-dev5
==========
Development
-----------
-  Tests now run on tox.
-  Added Google Groups and Twitter link.

0.0.1-dev4
==========

Fixes
-----
-  Missing property setters in ``boofuzz.request.Request`` now implemented.
-  Unit tests now pass on Windows.
-  Fixed wheel build issue; boofuzz subpackages were missing.

0.0.1-dev3
==========

Fixes
-----
-  Session constructor param ``session_filename`` is now optional.

0.0.1-dev2
==========
New features
------------

-  Now on PyPI! ``pip install boofuzz``
-  API is now centralized so all classes are available at top level
   ``boofuzz.*``

   -  This makes it way easier to use. Everything can be used like
      ``boofuzz.MyClass`` instead of ``boofuzz.my_file.MyClass``.

-  Added ``EzOutletReset`` class to support restarting devices using an
   ezOutlet EZ-11b.

Backwards-incompatible
----------------------

-  Target now only takes an ``ITargetConnection``. This separates
   responsibilities and makes our code more flexible with different
   kinds of connections.

Fixes
-----

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
---------------------

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
-----

-  Continuous integration with Travis is running!
-  Doc organization improvements.
-  Can now install with extras ``[dev]``

Initial Development Release - 0.0.1-dev1
========================================


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
