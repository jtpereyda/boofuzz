import threading
import time


class DebuggerThreadPydbg(threading.Thread):
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
        self.dbg.set_callback(pydbg.defines.USER_CALLBACK_DEBUG_EVENT, self._dbg_callback_user)
        self.dbg.set_callback(pydbg.defines.EXCEPTION_ACCESS_VIOLATION, self._dbg_callback_access_violation)

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
            try:
                self.dbg.attach(self.pid)
            except pydbg.pdx as e:
                self.process_monitor.log("error: pydbg: {0}".format(str(e).rstrip()))
                if "The request is not supported." in str(e):
                    self.process_monitor.log("Are you trying to start a 64-bit process? pydbg as of this writing only"
                                             " supports targeting 32-bit processes.")
                elif "Access is denied." in str(e):
                    self.process_monitor.log("It may be that your process died before it could be attached.")
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