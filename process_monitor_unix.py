import os
import sys
import threading
import time

import click

from boofuzz import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer

'''
By nnp
http://www.unprotectedhex.com

This intended as a basic replacement for Sulley's process_monitor.py on *nix.
The below options are accepted. Crash details are limited to the signal that
caused the death and whatever operating system supported mechanism is in place (i.e
core dumps)

Replicated methods:
    - alive
    - log
    - post_send
    - pre_send
    - start_target
    - stop_target
    - set_start_commands
    - set_stop_commands

Limitations
    - Cannot attach to an already running process
    - Currently only accepts one start_command
    - Limited 'crash binning'. Relies on the availability of core dumps. These
      should be created in the same directory the process is ran from on Linux
      and in the (hidden) /cores directory on OS X. On OS X you have to add 
      the option COREDUMPS=-YES- to /etc/hostconfig and then `ulimit -c
      unlimited` as far as I know. A restart may be required. The file
      specified by crash_bin will any other available details such as the test
      that caused the crash and the signal received by the program
'''

ERR = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)


class NIXProcessMonitorPedrpcServer(ProcessMonitorPedrpcServer):
    def __init__(self, host, port, cbin, coredump_dir, proc_name, ignore_pid, level=1):
        """
        @type host: str
        @param host: Hostname or IP address
        @type port: int
        @param port: Port to bind server to
        @type cbin: str
        @param cbin: Where to save monitored process crashes for analysis
        """
        super(NIXProcessMonitorPedrpcServer, self).__init__(host, port, cbin,DebuggerThreadSimple, proc_name, ignore_pid, level)

        self.crash_bin = cbin
        self.log_level = level
        self.dbg = None
        self.last_synopsis = None
        self.test_number = 0
        self.start_commands = []
        self.stop_commands = []
        self.proc_name = None
        self.coredump_dir = coredump_dir
        self.debugger_thread = None
        self.log("Process Monitor PED-RPC server initialized:")
        self.log("Listening on %s:%s" % (host, port))
        self.log("awaiting requests...")

    def post_send(self):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        Returns:
            bool: True if the target is still active, False otherwise.
        """
        if self.debugger_thread.isAlive():
            return True
        else:
            rec_file = open(self.crash_bin, 'a')
            rec_file.write(self.last_synopsis)
            rec_file.close()

            if self.coredump_dir is not None:
                dest = os.path.join(self.coredump_dir, str(self.test_number))
                src = self._get_coredump_path()

                if src is not None:
                    self.log("moving core dump %s -> %s" % (src, dest))
                    os.rename(src, dest)
            return False

    def _get_coredump_path(self):
        """
        This method returns the path to the coredump file if one was created
        """
        if sys.platform == 'linux' or sys.platform == 'linux2':
            path = './core'
            if os.path.isfile(path):
                return path

        return None

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

    def start_target(self):
        """
        Start up the target process by issuing the commands in self.start_commands.

        @returns True if successful. No failure detection yet.
        """
        self.log("creating debugger thread", 5)
        self.dbg = DebuggerThreadSimple(self.start_commands, self, log_level=self.log_level)
        self.dbg.spawn_target()
        # prevent blocking by spawning off another thread to waitpid
        self.debugger_thread = threading.Thread(target=self.dbg.start_monitoring)
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
        if self.debugger_thread is not None and self.debugger_thread.isAlive():
            if len(self.stop_commands) < 1:
                self.dbg.stop_target()
            else:
                for command in self.stop_commands:
                    if command == "TERMINATE_PID":
                        self.dbg.stop_target()
                    else:
                        os.system(command)
            self.log("target stopped")
        else:
            self.log("target already stopped")


def serve_procmon(port, crash_bin, proc_name, ignore_pid, log_level, coredump_dir):
    with NIXProcessMonitorPedrpcServer(host="0.0.0.0", port=port, cbin=crash_bin, coredump_dir=coredump_dir,
                                       proc_name=proc_name, ignore_pid=ignore_pid, level=log_level) as servlet:
        servlet.serve_forever()


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
@click.option('--coredump-dir', '--coredump_dir', '-d',
              help='directory where coredumps are moved to (you may need to adjust ulimits to create coredumps)')
def go(crash_bin, ignore_pid, log_level, proc_name, port, coredump_dir):
    if coredump_dir is not None and not os.path.isdir(coredump_dir):
        ERR("coredump_dir must be an existing directory")

    serve_procmon(port=port,
                  crash_bin=crash_bin,
                  proc_name=proc_name,
                  ignore_pid=ignore_pid,
                  log_level=log_level,
                  coredump_dir=coredump_dir
                  )


if __name__ == "__main__":
    go()
