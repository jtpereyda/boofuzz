IFuzzLogger Interface
=====================
IFuzzLogger provides the logging interface for the Sulley framework and test
writers.

The methods provided are meant to mirror functional test actions. Instead of
generic debug/info/warning methods, IFuzzLogger provides a means for logging
test cases, passes, failures, test steps, etc.