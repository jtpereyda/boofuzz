from __future__ import print_function
import os
import signal
import subprocess
import sys
import time


class DebuggerThreadSimple:
    def __init__(self, start_commands, process_monitor, log_level):
        """
        This class isn't actually ran as a thread, only the start_monitoring
        method is. It can spawn/stop a process, wait for it to exit and report on
        the exit status/code.
        """

        self.start_commands = start_commands
        self.process_monitor = process_monitor
        # if isinstance(start_commands, basestring):
        #     self.tokens = start_commands.split(' ')
        # else:
        #     self.tokens = start_commands
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
        self.alive = False
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
                print('WindowsError "{0}" while starting "{1}"'.format(e.strerror, command), file=sys.stderr)
                return False
        self.log("done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        self.pid = self._process.pid

    def start_monitoring(self):
        """
        self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        while self.exit_status == (0, 0):
            self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        """

        self.exit_status = os.waitpid(self.pid, 0)
        # [0] is the pid
        self.exit_status = self.exit_status[1]

        self.alive = False

        if os.WCOREDUMP(self.exit_status):
            reason = 'Segmentation fault'
        elif os.WIFSTOPPED(self.exit_status):
            reason = 'Stopped with signal ' + str(os.WTERMSIG(self.exit_status))
        elif os.WIFSIGNALED(self.exit_status):
            reason = 'Terminated with signal ' + str(os.WTERMSIG(self.exit_status))
        elif os.WIFEXITED(self.exit_status):
            reason = 'Exit with code - ' + str(os.WEXITSTATUS(self.exit_status))
        else:
            reason = 'Process died for unknown reason'

        self.process_monitor.last_synopsis = '[{0}] Crash : Reason - {1}\n'.format(time.strftime("%I:%M.%S"), reason)

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError as e:
            print(e.errno)  # TODO interpret some basic errors
        else:
            self.alive = False

    def is_alive(self):
        return self.alive
