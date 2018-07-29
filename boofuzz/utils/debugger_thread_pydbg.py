from __future__ import print_function
import os
import subprocess
import threading
import time
import sys

import pydbg
import pydbg.defines

if not getattr(__builtins__, "WindowsError", None):
    class WindowsError(OSError):
        pass


class DebuggerThreadPydbg(threading.Thread):
    def __init__(self, start_commands, process_monitor, proc_name=None, ignore_pid=None, pid=None, log_level=1):
        """
        Instantiate a new PyDbg instance and register user and access violation callbacks.
        """
        threading.Thread.__init__(self)

        self.start_commands = start_commands
        self.process_monitor = process_monitor
        self.finished_starting = threading.Event()
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
        self.dbg.set_callback(pydbg.defines.USER_CALLBACK_DEBUG_EVENT, self._dbg_callback_user)
        self.dbg.set_callback(pydbg.defines.EXCEPTION_ACCESS_VIOLATION, self._dbg_callback_access_violation)
        self.log_level = log_level
        self._process = None

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print("[%s] %s" % (time.strftime("%I:%M.%S"), msg))

    def _dbg_callback_access_violation(self, dbg):
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

    def _dbg_callback_user(self, dbg):
        """
        The user callback is run roughly every 100 milliseconds (WaitForDebugEvent() timeout from pydbg_core.py). Simply
        check if the active flag was lowered and if so detach from the target process. The thread should then exit.
        """

        if not self.active:
            self.process_monitor.log("debugger thread-%s detaching" % self.getName(), 5)
            dbg.detach()

        return pydbg.defines.DBG_CONTINUE

    def spawn_target(self):
        # TODO move spawn_target into run to remove the half-initialized state between calling the two functions
        # TODO checks: debugger thread already active; process already started; no start_commands

        self.log("starting target process")
        for command in self.start_commands:
            try:
                self._process = subprocess.Popen(command)
            except WindowsError as e:
                print('WindowsError "{0}" while starting "{1}"'.format(e.strerror, command), file=sys.stderr)
                return False
        self.log("done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        self.pid = self._process.pid

    def run(self):
        """
        Main thread routine, called on thread.start(). Thread exits when this routine returns.
        """
        self.spawn_target()

        if self.proc_name is not None or self.pid is not None:

            # watch for and try attaching to the process.
            if self.pid is None and self.proc_name is not None:
                self.process_monitor.log(
                    "debugger thread-%s looking for process name: %s" % (self.getName(), self.proc_name))
                self.watch()
            self.process_monitor.log("debugger thread-%s attaching to pid: %s" % (self.getName(), self.pid))
            try:
                self.dbg.attach(self.pid)
            except pydbg.pdx as e:
                self.process_monitor.log("error: pydbg: {0}".format(str(e).rstrip()))
                if "The request is not supported." in str(e):
                    self.process_monitor.log("Are you trying to start a 64-bit process? pydbg as of this writing only"
                                             " supports targeting 32-bit processes.")
                elif "Access is denied." in str(e):
                    self.process_monitor.log("It may be that your process died before it could be attached.")
            self.finished_starting.set()
            self.dbg.run()
            self.process_monitor.log("debugger thread-%s exiting" % self.getName())

            # TODO: removing the following line appears to cause some concurrency issues.
            # del self.dbg

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

    def stop_target(self):
        try:
            os.system("taskkill /pid %d" % self.pid)
        except OSError as e:
            print(e.errno)  # TODO interpret some basic errors

    def pre_send(self):
        # un-serialize the crash bin from disk. this ensures we have the latest copy (ie: vmware image is cycling).
        self.process_monitor.crash_bin.import_file(self.process_monitor.crash_filename)

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        av = self.access_violation

        # if there was an access violation, wait for the debugger thread to finish then kill thread handle.
        # it is important to wait for the debugger thread to finish because it could be taking its sweet ass time
        # uncovering the details of the access violation.
        if av:
            while self.isAlive():
                time.sleep(1)

        # serialize the crash bin to disk.
        self.process_monitor.crash_bin.export_file(self.process_monitor.crash_filename)
        return not av
