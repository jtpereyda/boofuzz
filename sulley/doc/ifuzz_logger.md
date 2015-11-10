IFuzzLogger Interface
=====================
IFuzzLogger provides the logging interface for the Sulley framework and test
writers.

The methods provided are meant to mirror functional test actions. Instead of
generic debug/info/warning methods, IFuzzLogger provides a means for logging
test cases, passes, failures, test steps, etc.

This hypothetical sample output gives an idea of how the logger should be used:

    Test Case: UDP.Header.Address 3300
        Test Step: Fuzzing
            Send: 45 00 13 ab 00 01 40 00 40 11 c9 ...
        Test Step: Process monitor check
            Check OK
        Test Step: DNP Check
            Send: ff ff ff ff ff ff 00 0c 29 d1 10 ...
            Recv: 00 0c 29 d1 10 81 00 30 a7 05 6e ...
            Check: Reply is as expected.
            Check OK
    Test Case: UDP.Header.Address 3301
        Test Step: Fuzzing
            Send: 45 00 13 ab 00 01 40 00 40 11 c9 ...
        Test Step: Process monitor check
            Check Failed: "Process returned exit code 1"
        Test Step: DNP Check
            Send: ff ff ff ff ff ff 00 0c 29 d1 10 ...
            Recv: None
            Check: Reply is as expected.
            Check Failed

A test case is opened for each fuzzing case. A test step is opened for each
high-level test step. Test steps can include:

 * Fuzzing
 * Set up (pre-fuzzing)
 * Post-test cleanup
 * Instrumentation checks
 * Reset due to failure

Within a test step, a test may log data sent, data received, checks, check
results, and other information.
