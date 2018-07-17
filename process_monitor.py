#!c:\\python\\python.exe
from __future__ import print_function

import click
from boofuzz import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_pydbg import DebuggerThreadPydbg
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer


def serve_procmon(port, crash_bin, proc_name, ignore_pid, log_level):
    with ProcessMonitorPedrpcServer(host="0.0.0.0", port=port, crash_filename=crash_bin,
                                    debugger_class=DebuggerThreadPydbg, proc_name=proc_name, pid_to_ignore=ignore_pid,
                                    level=log_level, coredump_dir=None) as servlet:
        servlet.serve_forever()


# app.args.add_argument("-c", "--crash_bin", help='filename to serialize crash bin class to',
#                       default='boofuzz-crash-bin', metavar='FILENAME')
# app.args.add_argument("-i", "--ignore_pid", help='PID to ignore when searching for target process', type=int,
#                       metavar='PID')
# app.args.add_argument("-l", "--log_level", help='log level: default 1, increase for more verbosity', type=int,
#                       default=1, metavar='LEVEL')
# app.args.add_argument("-p", "--proc_name", help='process name to search for and attach to', metavar='NAME')
# app.args.add_argument("-P", "--port", help='TCP port to bind this agent to', type=int, default=DEFAULT_PROCMON_PORT)
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
def go(crash_bin, ignore_pid, log_level, proc_name, port):
    serve_procmon(port=port,
                  crash_bin=crash_bin,
                  proc_name=proc_name,
                  ignore_pid=ignore_pid,
                  log_level=log_level,
                  )


if __name__ == "__main__":
    go()
