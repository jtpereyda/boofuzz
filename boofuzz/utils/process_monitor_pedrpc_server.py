from __future__ import print_function

import os
import shlex
import time

from boofuzz import pedrpc
from boofuzz import utils


def _split_command_if_str(command):
    """Splits a shell command string into a list of arguments.

    If any individual item is not a string, item is returned unchanged.

    Designed for use with subprocess.Popen.

    Args:
        command (Union[basestring, :obj:`list` of :obj:`basestring`]): List of commands. Each command
        should be a string or a list of strings.

    Returns:
        (:obj:`list` of :obj:`list`: of :obj:`str`): List of lists of command arguments.
    """
    if isinstance(command, basestring):
        return shlex.split(command)
    else:
        return command


class ProcessMonitorPedrpcServer(pedrpc.Server):
    def __init__(self, host, port, crash_filename, debugger_class, proc_name=None, pid_to_ignore=None, level=1, coredump_dir=None):
        """
        @type  host:           str
        @param host:           Hostname or IP address
        @type  port:           int
        @param port:           Port to bind server to
        @type  crash_filename: str
        @param crash_filename: Name of file to (un)serialize crash bin to/from
        @type  proc_name:           str
        @param proc_name:           (Optional, def=None) Process name to search for and attach to
        @type  pid_to_ignore:  int
        @param pid_to_ignore:  (Optional, def=None) Ignore this PID when searching for the target process
        @type  level:          int
        @param level:          (Optional, def=1) Log output level, increase for more verbosity
        """

        # initialize the PED-RPC server.
        pedrpc.Server.__init__(self, host, port)

        self.crash_filename = os.path.abspath(crash_filename)
        self.debugger_class = debugger_class
        self.proc_name = proc_name
        self.ignore_pid = pid_to_ignore
        self.log_level = level

        self.stop_commands = []
        self.start_commands = []
        self.test_number = None
        self.debugger_thread = None
        self.crash_bin = utils.crash_binning.CrashBinning()

        self.last_synopsis = ""

        self.coredump_dir = coredump_dir

        if not os.access(os.path.dirname(self.crash_filename), os.X_OK):
            self.log("invalid path specified for crash bin: %s" % self.crash_filename)
            raise Exception

        self.log("Process Monitor PED-RPC server initialized:")
        self.log("\t listening on:  %s:%s" % (host, port))
        self.log("\t crash file:    %s" % self.crash_filename)
        self.log("\t # records:     %d" % len(self.crash_bin.bins))
        self.log("\t proc name:     %s" % self.proc_name)
        self.log("\t log level:     %d" % self.log_level)
        self.log("awaiting requests...")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.debugger_thread is not None and self.debugger_thread.isAlive():
            self.debugger_thread.stop_target()

    # noinspection PyMethodMayBeStatic
    def alive(self):
        """
        Returns True. Useful for PED-RPC clients who want to see if the PED-RPC connection is still alive.
        """

        return True

    def get_crash_synopsis(self):
        """
        Return the last recorded crash synopsis.

        @rtype:  String
        @return: Synopsis of last recorded crash.
        """

        return self.last_synopsis

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print("[%s] %s" % (time.strftime("%I:%M.%S"), msg))

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        if self.debugger_thread is not None:
            return self.debugger_thread.post_send()
        else:
            raise Exception("post_send called before pre_send!")

    def pre_send(self, test_number):
        """
        This routine is called before the fuzzer transmits a test case and ensure the debugger thread is operational.

        @type  test_number: Integer
        @param test_number: Test number to retrieve PCAP for.
        """
        self.log("pre_send(%d)" % test_number, 10)
        self.test_number = test_number

        if self.debugger_thread is None or not self.debugger_thread.isAlive():
            self.start_target()
            self.debugger_thread.pre_send()

    def start_target(self):
        """
        Start up the target process by issuing the commands in self.start_commands.

        @returns True if successful.
        """
        self.log('Starting target...')
        self.log("creating debugger thread", 5)
        self.debugger_thread = self.debugger_class(self.start_commands, self, proc_name=self.proc_name,
                                                   ignore_pid=self.ignore_pid, log_level=self.log_level)
        self.debugger_thread.daemon = True
        self.debugger_thread.start()
        self.debugger_thread.finished_starting.wait()
        self.log("giving debugger thread 2 seconds to settle in", 5)
        time.sleep(2)
        return True

    def stop_target(self):
        """
        Kill the current debugger thread and stop the target process by issuing the commands in self.stop_commands.
        """
        self.log('Stopping target...')
        # give the debugger thread a chance to exit.
        time.sleep(1)

        if self.debugger_thread is not None and self.debugger_thread.isAlive():
            if len(self.stop_commands) < 1:
                self.debugger_thread.stop_target()
            else:
                for command in self.stop_commands:
                    if command == "TERMINATE_PID":
                        self.debugger_thread.stop_target()
                    else:
                        self.log("Executing stop command: '{0}'".format(command), 2)
                        os.system(command)
            self.log("target stopped")
        else:
            self.log("target already stopped")

    def restart_target(self):
        """
        Stop and start the target process.

        @returns True if successful.
        """
        self.log('Restarting target...')
        self.stop_target()
        return self.start_target()

    def set_proc_name(self, new_proc_name):
        self.log("updating target process name to '%s'" % new_proc_name)
        self.proc_name = new_proc_name

    def set_start_commands(self, new_start_commands):
        self.log("updating start commands to: {0}".format(list(new_start_commands)))
        self.start_commands = map(_split_command_if_str, new_start_commands)

    def set_stop_commands(self, new_stop_commands):
        self.log("updating stop commands to: {0}".format(list(new_stop_commands)))
        self.stop_commands = new_stop_commands
        self.stop_commands = map(_split_command_if_str, new_stop_commands)
