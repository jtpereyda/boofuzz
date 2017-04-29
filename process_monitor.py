#!c:\\python\\python.exe
from __future__ import print_function
import subprocess
import threading
import time
import sys
import os

import pydbg
import pydbg.defines
from cement.core.foundation import CementApp

from boofuzz import utils
from boofuzz import pedrpc

DEFAULT_PORT = 26002


class DebuggerThread(threading.Thread):
    def __init__(self, process_monitor, proc_name=None, ignore_pid=None, pid=None):
        """
        Instantiate a new PyDbg instance and register user and access violation callbacks.
        """

        threading.Thread.__init__(self)

        self.process_monitor = process_monitor
        self.proc_name = proc_name
        self.ignore_pid = ignore_pid

        self.access_violation = False
        self.active = True
        self.dbg = pydbg.pydbg()
        self.pid = pid

        # give this thread a unique name.
        self.setName("%d" % time.time())

        self.process_monitor.log("debugger thread initialized with UID: %s" % self.getName(), 5)

        # set the user callback which is response for checking if this thread has been killed.
        self.dbg.set_callback(pydbg.defines.USER_CALLBACK_DEBUG_EVENT, self.dbg_callback_user)
        self.dbg.set_callback(pydbg.defines.EXCEPTION_ACCESS_VIOLATION, self.dbg_callback_access_violation)

    def dbg_callback_access_violation(self, dbg):
        """
        Ignore first chance exceptions. Record all unhandled exceptions to the process monitor crash bin and kill
        the target process.
        """

        # ignore first chance exceptions.
        if dbg.dbg.u.Exception.dwFirstChance:
            return pydbg.defines.DBG_EXCEPTION_NOT_HANDLED

        # raise the access violation flag.
        self.access_violation = True

        # record the crash to the process monitor crash bin.
        # include the test case number in the "extra" information block.
        self.process_monitor.crash_bin.record_crash(dbg, self.process_monitor.test_number)

        # save the the crash synopsis.
        self.process_monitor.last_synopsis = self.process_monitor.crash_bin.crash_synopsis()
        first_line = self.process_monitor.last_synopsis.split("\n")[0]

        self.process_monitor.log("debugger thread-%s caught access violation: '%s'" % (self.getName(), first_line))

        # this instance of pydbg should no longer be accessed, i want to know if it is.
        self.process_monitor.crash_bin.pydbg = None

        # kill the process.
        dbg.terminate_process()
        return pydbg.defines.DBG_CONTINUE

    def dbg_callback_user(self, dbg):
        """
        The user callback is run roughly every 100 milliseconds (WaitForDebugEvent() timeout from pydbg_core.py). Simply
        check if the active flag was lowered and if so detach from the target process. The thread should then exit.
        """

        if not self.active:
            self.process_monitor.log("debugger thread-%s detaching" % self.getName(), 5)
            dbg.detach()

        return pydbg.defines.DBG_CONTINUE

    def run(self):
        """
        Main thread routine, called on thread.start(). Thread exits when this routine returns.
        """

        if self.proc_name is not None or self.pid is not None:

            # watch for and try attaching to the process.
            if self.pid is None and self.proc_name is not None:
                self.process_monitor.log(
                    "debugger thread-%s looking for process name: %s" % (self.getName(), self.proc_name))
                self.watch()
            self.process_monitor.log("debugger thread-%s attaching to pid: %s" % (self.getName(), self.pid))
            self.dbg.attach(self.pid)
            self.dbg.run()
            self.process_monitor.log("debugger thread-%s exiting" % self.getName())

            # TODO: removing the following line appears to cause some concurrency issues.
            del self.dbg

    def watch(self):
        """
        Continuously loop, watching for the target process. This routine "blocks" until the target process is found.
        Update self.pid when found and return.
        """

        while not self.pid:
            for (pid, name) in self.dbg.enumerate_processes():
                # ignore the optionally specified PID.
                if pid == self.ignore_pid:
                    continue

                if name.lower() == self.proc_name.lower():
                    self.pid = pid
                    break

        self.process_monitor.log("debugger thread-%s found match on pid %d" % (self.getName(), self.pid))


class ProcessMonitorPedrpcServer(pedrpc.Server):
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

        # initialize the PED-RPC server.
        pedrpc.Server.__init__(self, host, port)

        self.crash_filename = os.path.abspath(crash_filename)
        self.proc_name = proc
        self.ignore_pid = pid_to_ignore
        self.log_level = level

        self.stop_commands = []
        self.start_commands = []
        self._process = None
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
        if self._process is not None:
            self._process.kill()

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

    def get_bin_keys(self):
        """
        Return the crash bin keys, ie: the unique list of exception addresses.

        @rtype:  List
        @return: List of crash bin exception addresses (keys).
        """

        return self.crash_bin.bins.keys()

    def get_bin(self, binary):
        """
        Return the crash entries from the specified bin or False if the bin key is invalid.

        @type  binary: Integer (DWORD)
        @param binary: Crash bin key (ie: exception address)

        @rtype:  list
        @return: List of crashes in specified bin.
        """

        if binary not in self.crash_bin.bins:
            return False

        return self.crash_bin.bins[binary]

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

        @rtype:  bool
        @return: Return True if the target is still active, False otherwise.
        """

        crashes = 0
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
            # for binary in self.crash_bin.bins.keys():
            # crashes += len(self.crash_bin.bins[binary])
            for binary, crash_list in self.crash_bin.bins.items():
                crashes += len(crash_list)
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
        try:
            self.crash_bin.import_file(self.crash_filename)
        except Exception:
            pass

        self.start_target()

    def start_target(self):
        """
        Start up the target process by issuing the commands in self.start_commands.

        @returns True if successful.
        """
        # if we don't already have a debugger thread or process, start one now.
        if (not self.debugger_thread or not self.debugger_thread.isAlive()) and (self._process is None or self._process.poll() is not None):
            if len(self.start_commands) > 0:
                self.log("starting target process")

                for command in self.start_commands:
                    try:
                        self._process = subprocess.Popen(command)
                    except WindowsError as e:
                        print('WindowsError "{0}" while starting "{1}"'.format(e.strerror, command), file=sys.stderr)
                        return False

                self.log("done. target up and running, giving it 5 seconds to settle in.")
                time.sleep(5)

            if self._process is not None:
                self.log("creating debugger thread", 5)
                self.debugger_thread = DebuggerThread(self, proc_name=self.proc_name, ignore_pid=self.ignore_pid,
                                                      pid=self._process.pid)
                self.debugger_thread.daemon = True
                self.debugger_thread.start()
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

        if len(self.stop_commands) < 1:
            self._process.kill()
        else:
            for command in self.stop_commands:
                if command == "TERMINATE_PID":
                    dbg = pydbg.pydbg()
                    for (pid, name) in dbg.enumerate_processes():
                        if name.lower() == self.proc_name.lower():
                            os.system("taskkill /pid %d" % pid)
                            break
                else:
                    os.system(command)

    def restart_target(self):
        """
        Stop and start the target process.

        @returns True if successful.
        """
        self.stop_target()
        return self.start_target()

    def set_proc_name(self, new_proc_name):
        self.log("updating target process name to '%s'" % new_proc_name)
        self.proc_name = new_proc_name

    def set_start_commands(self, new_start_commands):
        self.log("updating start commands to: %s" % new_start_commands)
        self.start_commands = new_start_commands

    def set_stop_commands(self, new_stop_commands):
        self.log("updating stop commands to: %s" % new_stop_commands)
        self.stop_commands = new_stop_commands


def serve_procmon(port, crash_bin, proc_name, ignore_pid, log_level):
    with ProcessMonitorPedrpcServer(host="0.0.0.0", port=port, crash_filename=crash_bin, proc=proc_name,
                                    pid_to_ignore=ignore_pid, level=log_level) as servlet:
        servlet.serve_forever()


class ProcessMonitorApp(CementApp):
    class Meta:
        label = 'procmon'


def main():
    with ProcessMonitorApp() as app:
        app.args.add_argument('-f', '--foo', action='store', metavar='STR',
                              help='the notorious foo option')
        app.args.add_argument("-c", "--crash_bin", help='filename to serialize crash bin class to', default='crash-bin',
                              metavar='FILENAME')
        app.args.add_argument("-i", "--ignore_pid", help='PID to ignore when searching for target process', type=int,
                              metavar='PID')
        app.args.add_argument("-l", "--log_level", help='log level: default 1, increase for more verbosity', type=int,
                              default=1, metavar='LEVEL')
        app.args.add_argument("-p", "--proc_name", help='process name to search for and attach to', metavar='NAME')
        app.args.add_argument("-P", "--port", help='TCP port to bind this agent to', type=int, default=DEFAULT_PORT)

        app.run()  # parses args

        serve_procmon(port=app.pargs.port,
                      crash_bin=app.pargs.crash_bin,
                      proc_name=app.pargs.proc_name,
                      ignore_pid=app.pargs.ignore_pid,
                      log_level=app.pargs.log_level)


if __name__ == "__main__":
    main()
