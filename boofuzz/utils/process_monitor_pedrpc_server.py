from __future__ import print_function
from threading import Event
import time
import os


from boofuzz import utils
from boofuzz import pedrpc


class ProcessMonitorPedrpcServer(pedrpc.Server):
    def __init__(self, host, port, crash_filename, debugger_class, proc=None, pid_to_ignore=None, level=1):
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

        # initialize the PED-RPC server.
        pedrpc.Server.__init__(self, host, port)

        self.crash_filename = os.path.abspath(crash_filename)
        self.debugger_class = debugger_class
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

    def start_target(self):
        """
        Start up the target process by issuing the commands in self.start_commands.

        @returns True if successful.
        """
        self.log("creating debugger thread", 5)
        finished_starting = Event()
        self.debugger_thread = self.debugger_class(self.start_commands, self, finished_starting, proc_name=self.proc_name,
                                                   ignore_pid=self.ignore_pid, log_level=self.log_level)
        self.debugger_thread.daemon = True
        self.debugger_thread.start()
        finished_starting.wait()
        self.log("giving debugger thread 2 seconds to settle in", 5)
        time.sleep(2)
        return True

    def stop_target(self):
        """
        Kill the current debugger thread and stop the target process by issuing the commands in self.stop_commands.
        """
        # give the debugger thread a chance to exit.
        time.sleep(1)

        self.log("stopping target process")
        if self.debugger_thread is not None and self.debugger_thread.isAlive():
            if len(self.stop_commands) < 1:
                self.debugger_thread.stop_target()
            else:
                for command in self.stop_commands:
                    if command == "TERMINATE_PID":
                        self.debugger_thread.stop_target()
                    else:
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
        self.log("updating start commands to: %s" % list(new_start_commands))
        self.start_commands = new_start_commands

    def set_stop_commands(self, new_stop_commands):
        self.log("updating stop commands to: %s" % list(new_stop_commands))
        self.stop_commands = new_stop_commands
