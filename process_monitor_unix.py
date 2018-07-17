import os
import sys

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
