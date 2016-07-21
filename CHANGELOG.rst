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
