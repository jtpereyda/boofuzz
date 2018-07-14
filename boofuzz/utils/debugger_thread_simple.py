import os
import signal
import subprocess


class DebuggerThreadSimple:
    def __init__(self, start_command):
        """
        This class isn't actually ran as a thread, only the start_monitoring
        method is. It can spawn/stop a process, wait for it to exit and report on
        the exit status/code.
        """

        self.start_command = start_command
        if isinstance(start_command, basestring):
            self.tokens = start_command.split(' ')
        else:
            self.tokens = start_command
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
        self.alive = False

    def spawn_target(self):
        print self.tokens
        self.pid = subprocess.Popen(self.tokens).pid
        self.alive = True

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

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except OSError as e:
            print e.errno  # TODO interpret some basic errors
        else:
            self.alive = False

    def is_alive(self):
        return self.alive