#!c:\\python\\python.exe
from __future__ import print_function

import os
import time

import click
from boofuzz import DEFAULT_PROCMON_PORT
from boofuzz import utils
from boofuzz.utils.debugger_thread_pydbg import DebuggerThreadPydbg
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer


class ProcessMonitorPedrpcServerWindows(ProcessMonitorPedrpcServer):
    def __init__(self, host, port, crash_filename, proc=None, pid_to_ignore=None, level=1):
        """
        @type  host:           str
        @param host:           Hostname or IP address
        @type  port:           int
        @param port:           Port to bind server to
        @type  crash_filename: str
        @param crash_filename: Name of file to (un)serialize crash bin to/from
        @type  proc:           str
        @param proc:           (Optional, def=None) Process name to search for and attach to
        @type  pid_to_ignore:  int
        @param pid_to_ignore:  (Optional, def=None) Ignore this PID when searching for the target process
        @type  level:          int
        @param level:          (Optional, def=1) Log output level, increase for more verbosity
        """
        super(ProcessMonitorPedrpcServerWindows, self).__init__(host, port, crash_filename, DebuggerThreadPydbg, proc, pid_to_ignore, level)

        self.crash_filename = os.path.abspath(crash_filename)
        self.proc_name = proc
        self.ignore_pid = pid_to_ignore
        self.log_level = level

        self.stop_commands = []
        self.start_commands = []
        self.test_number = None
        self.debugger_thread = None
        self.crash_bin = utils.crash_binning.CrashBinning()

        self.last_synopsis = ""

        if not os.access(os.path.dirname(self.crash_filename), os.X_OK):
            self.log("invalid path specified for crash bin: %s" % self.crash_filename)
            raise Exception

        # restore any previously recorded crashes.
        try:
            self.crash_bin.import_file(self.crash_filename)
        except Exception:
            pass

        self.log("Process Monitor PED-RPC server initialized:")
        self.log("\t crash file:  %s" % self.crash_filename)
        self.log("\t # records:   %d" % len(self.crash_bin.bins))
        self.log("\t proc name:   %s" % self.proc_name)
        self.log("\t log level:   %d" % self.log_level)
        self.log("awaiting requests...")

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        if self.debugger_thread is None:
            return True
        else:
            av = self.debugger_thread.access_violation

            # if there was an access violation, wait for the debugger thread to finish then kill thread handle.
            # it is important to wait for the debugger thread to finish because it could be taking its sweet ass time
            # uncovering the details of the access violation.
            if av:
                while self.debugger_thread.isAlive():
                    time.sleep(1)

                self.debugger_thread = None

            # serialize the crash bin to disk.
            self.crash_bin.export_file(self.crash_filename)
            return not av

    def pre_send(self, test_number):
        """
        This routine is called before the fuzzer transmits a test case and ensure the debugger thread is operational.

        @type  test_number: Integer
        @param test_number: Test number to retrieve PCAP for.
        """
        self.log("pre_send(%d)" % test_number, 10)
        self.test_number = test_number

        # un-serialize the crash bin from disk. this ensures we have the latest copy (ie: vmware image is cycling).
        self.crash_bin.import_file(self.crash_filename)

        if self.debugger_thread is None or not self.debugger_thread.isAlive():
            self.start_target()



def serve_procmon(port, crash_bin, proc_name, ignore_pid, log_level):
    with ProcessMonitorPedrpcServerWindows(host="0.0.0.0", port=port, crash_filename=crash_bin, proc=proc_name,
                                           pid_to_ignore=ignore_pid, level=log_level) as servlet:
        servlet.serve_forever()


# app.args.add_argument("-c", "--crash_bin", help='filename to serialize crash bin class to',
#                       default='boofuzz-crash-bin', metavar='FILENAME')
# app.args.add_argument("-i", "--ignore_pid", help='PID to ignore when searching for target process', type=int,
#                       metavar='PID')
# app.args.add_argument("-l", "--log_level", help='log level: default 1, increase for more verbosity', type=int,
#                       default=1, metavar='LEVEL')
# app.args.add_argument("-p", "--proc_name", help='process name to search for and attach to', metavar='NAME')
# app.args.add_argument("-P", "--port", help='TCP port to bind this agent to', type=int, default=DEFAULT_PROCMON_PORT)
@click.command()
@click.option('--crash-bin', '--crash_bin', '-c', help='filename to serialize crash bin class to',
              default='boofuzz-crash-bin', metavar='FILENAME')
@click.option('--ignore-pid', '--ignore_pid', '-i', type=int, help='PID to ignore when searching for target process',
              metavar='PID')
@click.option('--log-level', '--log_level', '-l', help='log level: default 1, increase for more verbosity', type=int,
              default=1, metavar='LEVEL')
@click.option('--proc-name', '--proc_name', '-p', help='process name to search for and attach to',
              metavar='NAME')
@click.option('--port', '-P', help='TCP port to bind this agent to', type=int, default=DEFAULT_PROCMON_PORT)
def go(crash_bin, ignore_pid, log_level, proc_name, port):
    serve_procmon(port=port,
                  crash_bin=crash_bin,
                  proc_name=proc_name,
                  ignore_pid=ignore_pid,
                  log_level=log_level,
                  )


if __name__ == "__main__":
    go()
