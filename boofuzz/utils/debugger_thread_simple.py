from __future__ import print_function

import os
import signal
import subprocess
import sys
import threading
import time

import psutil

if not getattr(__builtins__, "WindowsError", None):
    class WindowsError(OSError):
        """Mock WindowsError since Linux Python lacks WindowsError"""
        @property
        def winerror(self):
            return self.errno
        pass


def _enumerate_processes():
    for pid in psutil.pids():
        yield (pid, psutil.Process(pid).name())


def _get_coredump_path():
    """
    This method returns the path to the coredump file if one was created
    """
    if sys.platform == 'linux' or sys.platform == 'linux2':
        path = './core'
        if os.path.isfile(path):
            return path

    return None


class DebuggerThreadSimple(threading.Thread):
    def __init__(self, start_commands, process_monitor, proc_name=None, ignore_pid=None,  log_level=1):
        """
        This class isn't actually ran as a thread, only the start_monitoring
        method is. It can spawn/stop a process, wait for it to exit and report on
        the exit status/code.
        """
        threading.Thread.__init__(self)

        self.proc_name = proc_name
        self.ignore_pid = ignore_pid
        self.start_commands = start_commands
        self.process_monitor = process_monitor
        self.finished_starting = threading.Event()
        # if isinstance(start_commands, basestring):
        #     self.tokens = start_commands.split(' ')
        # else:
        #     self.tokens = start_commands
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
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

    def spawn_target(self):
        self.log("starting target process")

        for command in self.start_commands:
            try:
                self._process = subprocess.Popen(command)
            except WindowsError as e:
                print('WindowsError {errno}: "{strerror} while starting "{cmd}"'
                      .format(errno=e.winerror, strerror=e.strerror, cmd=command), file=sys.stderr)
                return False
            except OSError as e:
                print('OSError {errno}: "{strerror} while starting "{cmd}"'
                      .format(errno=e.errno, strerror=e.strerror, cmd=command), file=sys.stderr)
                return False
        if self.proc_name:
            self.log("done. waiting for start command to terminate.")
            os.waitpid(self._process.pid, 0)
            self.log('searching for process by name "{0}"'.format(self.proc_name))
            self.watch()
            self._psutil_proc = psutil.Process(pid=self.pid)
            self.process_monitor.log("found match on pid %d".format(self.pid))
        else:
            self.log("done. target up and running, giving it 5 seconds to settle in.")
            time.sleep(5)
            self.pid = self._process.pid
        self.process_monitor.log("attached to pid: {0}".format(self.pid))

    def run(self):
        """
        self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        while self.exit_status == (0, 0):
            self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        """
        self.spawn_target()

        self.finished_starting.set()
        if self.proc_name:
            gone, _ = psutil.wait_procs([self._psutil_proc])
            self.exit_status = gone[0].returncode
        else:
            exit_info = os.waitpid(self.pid, 0)
            self.exit_status = exit_info[1]  # [0] is the pid

        default_reason = 'Process died for unknown reason'
        if self.exit_status is not None:
            if os.WCOREDUMP(self.exit_status):
                reason = 'Segmentation fault'
            elif os.WIFSTOPPED(self.exit_status):
                reason = 'Stopped with signal ' + str(os.WTERMSIG(self.exit_status))
            elif os.WIFSIGNALED(self.exit_status):
                reason = 'Terminated with signal ' + str(os.WTERMSIG(self.exit_status))
            elif os.WIFEXITED(self.exit_status):
                reason = 'Exit with code - ' + str(os.WEXITSTATUS(self.exit_status))
            else:
                reason = default_reason
        else:
            reason = default_reason

        self.process_monitor.last_synopsis = '[{0}] Crash. Exit code: {1}. Reason - {2}\n'.format(
            time.strftime("%I:%M.%S"),
            self.exit_status if self.exit_status is not None else '<unknown>',
            reason)

    def watch(self):
        """
        Continuously loop, watching for the target process. This routine "blocks" until the target process is found.
        Update self.pid when found and return.
        """
        self.pid = None
        while not self.pid:
            for (pid, name) in _enumerate_processes():
                # ignore the optionally specified PID.
                if pid == self.ignore_pid:
                    continue

                if name.lower() == self.proc_name.lower():
                    self.pid = pid
                    break

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError as e:
            print(e.errno)  # TODO interpret some basic errors

    def pre_send(self):
        pass

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        if self.isAlive():
            return True
        else:
            rec_file = open(self.process_monitor.crash_filename, 'a')
            rec_file.write(self.process_monitor.last_synopsis)
            rec_file.close()

            if self.process_monitor.coredump_dir is not None:
                dest = os.path.join(self.process_monitor.coredump_dir, str(self.process_monitor.test_number))
                src = _get_coredump_path()

                if src is not None:
                    self.log("moving core dump %s -> %s" % (src, dest))
                    os.rename(src, dest)
            return False
