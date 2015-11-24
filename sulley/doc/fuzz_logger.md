FuzzLogger Class
================
FuzzLogger takes logged data and directs it to the appropriate backends.
It aggregates an arbitrary number of logger backends, and functions like a
multiplexer.

Stats
-----
FuzzLogger may also maintain data on test results for use by Sulley, e.g.,
a list of failed test cases.

IFuzzLogger is FuzzLogger's interface.