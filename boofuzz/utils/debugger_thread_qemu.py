from __future__ import print_function

import os

from ..helpers import _reset_shm_map

try:
    import resource  # Linux only

    resource.setrlimit(  # Equivalent to: ulimit -c unlimited
        resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    )
except ImportError:
    pass
import shutil
import signal
import struct
import sys
import threading
import time

from io import open

import sysv_ipc

POPEN_COMMUNICATE_TIMEOUT_FOR_ALREADY_DEAD_TASK = 30

# QEMU_PATH = os.path.dirname(os.path.realpath(__file__)) + "/afl-qemu-trace"
QEMU_PATH = shutil.which("afl-qemu-trace")

# These AFL config settings must match AFL's config.h values
AFL_FORKSRV_FD = 198
AFL_MAP_SIZE_POW2 = 2 ** 16
AFL_SHM_ENV_VAR = "__AFL_SHM_ID"


class ForkServer:
    def __init__(self, args):
        self.hide_output = True
        self.pid = None
        self.forkserv_fd_to_server_out, self.forkserv_fd_to_server_in = os.pipe()
        self.forkserv_fd_from_server_out, self.forkserv_fd_from_server_in = os.pipe()

        self.shm = sysv_ipc.SharedMemory(None, sysv_ipc.IPC_CREX, size=AFL_MAP_SIZE_POW2)
        self.shm_id = self.shm.id
        self.shm_mv = memoryview(self.shm)
        _reset_shm_map(self.shm_mv)  # set to all zeros

        fork_pid = os.fork()  # fork to take advantage of inherited file descriptors
        if fork_pid == 0:
            self.child(args)
        else:
            self.parent()

    def child(self, args):
        """Execute afl-qemu-trace with appropriate inputs: target command args, env var settings, and file descriptors.
        """
        os.dup2(self.forkserv_fd_to_server_out, AFL_FORKSRV_FD)
        os.dup2(self.forkserv_fd_from_server_in, AFL_FORKSRV_FD + 1)

        if self.hide_output:
            null = open("/dev/null", "w")
            os.dup2(null.fileno(), 1)
            os.dup2(null.fileno(), 2)
            null.close()

        os.close(self.forkserv_fd_to_server_in)
        os.close(self.forkserv_fd_to_server_out)
        os.close(self.forkserv_fd_from_server_in)
        os.close(self.forkserv_fd_from_server_out)
        env = {"QEMU_LOG": "nochain",
               AFL_SHM_ENV_VAR: str(self.shm_id),
               }
        os.execve(QEMU_PATH, ["afl-qemu-trace"] + args, env)

    def parent(self):
        os.close(self.forkserv_fd_to_server_out)
        os.close(self.forkserv_fd_from_server_in)
        os.read(self.forkserv_fd_from_server_out, 4)

    def run(self):  # only the parent runs run()
        """Runs the testcase in QEMU (by sending a command to the fork server) and returns the pid.
        """
        os.write(self.forkserv_fd_to_server_in, b"\0\0\0\0")  # Tell AFL Fork Server to start the target
        pid = struct.unpack("I", os.read(self.forkserv_fd_from_server_out, 4))[0]  # Read PID from Fork Server
        self.pid = pid
        return pid

    def wait_for_status(self):
        status = None
        while True:
            try:
                status = os.read(self.forkserv_fd_from_server_out, 4)
            except OSError:
                continue
            break
        if status is not None:
            status = struct.unpack("I", status)[0]
        return status


def _get_coredump_path():
    """
    This method returns the path to the coredump file if one was created
    """
    if sys.platform == "linux" or sys.platform == "linux2":
        path = "./core"
        if os.path.isfile(path):
            return path

    return None


class DebuggerThreadQemu(threading.Thread):
    """Simple debugger that gets exit code, stdout/stderr from a target process.

    This class isn't actually ran as a thread, only the start_monitoring
    method is. It can spawn/stop a process, wait for it to exit and report on
    the exit status/code.
    """
    fork_server = None  # use class attribute due to the procmon's behavior of creating a new debugger thread on restart

    def __init__(
        self,
        start_commands,
        process_monitor,
        proc_name=None,
        ignore_pid=None,
        coredump_dir=None,
        log_level=1,
        capture_output=False,
        **kwargs
    ):
        threading.Thread.__init__(self)

        self.proc_name = proc_name
        self.ignore_pid = ignore_pid
        if len(start_commands) > 1:
            raise Exception("QEMU Debugger can run only one command")
        self.start_commands = start_commands
        self.process_monitor = process_monitor
        self.coredump_dir = coredump_dir
        self.capture_output = capture_output
        self.finished_starting = threading.Event()
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
        self.log_level = log_level
        self._process = None
        self.fork_server = None

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print("[%s] %s" % (time.strftime("%I:%M.%S"), msg))

    def spawn_target(self):
        """Spawn target and let it run. Used by run()."""
        self.log("starting target process via QEMU")

        command = self.start_commands[0]
        if DebuggerThreadQemu.fork_server is None:  # create fork server only once
            self.log("exec start command: {0}".format(command))
            DebuggerThreadQemu.fork_server = ForkServer(args=command)
            DebuggerThreadQemu.fork_server.run()
        else:
            self.log("Fork server already running; restarting via server")
            DebuggerThreadQemu.fork_server.run()
        self.fork_server = DebuggerThreadQemu.fork_server
        self.pid = self.fork_server.pid

        self.log("done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)
        self.process_monitor.log("attached to pid: {0}".format(self.pid))

    def run(self):
        """
        self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        while self.exit_status == (0, 0):
            self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        """
        self.spawn_target()

        self.finished_starting.set()

        self.exit_status = self.fork_server.wait_for_status()

        reason = "Process died for unknown reason"
        if self.exit_status is not None:
            if os.WCOREDUMP(self.exit_status):
                reason = "Segmentation fault"
            elif os.WIFSTOPPED(self.exit_status):
                reason = "Stopped with signal " + str(os.WTERMSIG(self.exit_status))
            elif os.WIFSIGNALED(self.exit_status):
                reason = "Terminated with signal " + str(os.WTERMSIG(self.exit_status))
            elif os.WIFEXITED(self.exit_status):
                reason = "Exit with code - " + str(os.WEXITSTATUS(self.exit_status))

        msg = "[{0}] Crash. Exit code: {1}. Reason - {2}\n".format(
            time.strftime("%I:%M.%S"), self.exit_status if self.exit_status is not None else "<unknown>", reason
        )
        self.process_monitor.last_synopsis = msg

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:  # process was already dead
            pass
        except OSError as e:
            print(
                'Error while killing process. PID: {0} errno: {1} "{2}"'.format(self.pid, e.errno, os.strerror(e.errno))
            )
            raise e

    def pre_send(self):
        pass

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        if self.is_alive():
            return True
        else:
            with open(self.process_monitor.crash_filename, "a") as rec_file:
                rec_file.write(self.process_monitor.last_synopsis)

            if self.process_monitor.coredump_dir is not None:
                dest = os.path.join(self.process_monitor.coredump_dir, str(self.process_monitor.test_number))
                src = _get_coredump_path()

                if src is not None:
                    self.log("moving core dump %s -> %s" % (src, dest))
                    os.rename(src, dest)
            return False

    @property
    def shm_mv(self):
        return self.fork_server.shm_mv
