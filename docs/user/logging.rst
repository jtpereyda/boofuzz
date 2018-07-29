.. _logging:

=======
Logging
=======

Boofuzz provides flexible logging. All logging classes implement :class:`IFuzzLogger <boofuzz.IFuzzLogger>`.
Built-in logging classes are detailed below.

To use multiple loggers at once, see :class:`FuzzLogger <boofuzz.FuzzLogger>`.

Logging Interface (IFuzzLogger)
===============================
.. autoclass:: boofuzz.IFuzzLogger
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: boofuzz.IFuzzLoggerBackend
    :members:
    :undoc-members:
    :show-inheritance:

Text Logging
============
.. autoclass:: boofuzz.FuzzLoggerText
    :members:
    :undoc-members:
    :show-inheritance:

CSV Logging
===========
.. autoclass:: boofuzz.FuzzLoggerCsv
    :members:
    :undoc-members:
    :show-inheritance:

File Logging
============
.. autoclass:: boofuzz.FuzzLoggerFile
    :members:
    :undoc-members:
    :show-inheritance:

FuzzLogger Object
=================
.. autoclass:: boofuzz.FuzzLogger
    :members:
    :undoc-members:
    :show-inheritance:
