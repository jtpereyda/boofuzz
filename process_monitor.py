#!c:\\python\\python.exe
import click

from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer


def serve_procmon(ip, port, crash_bin, proc_name, ignore_pid, log_level):
    with ProcessMonitorPedrpcServer(
        host=ip,
        port=port,
        crash_filename=crash_bin,
        debugger_class=DebuggerThreadSimple,
        proc_name=proc_name,
        pid_to_ignore=ignore_pid,
        level=log_level,
        coredump_dir=None,
    ) as servlet:
        servlet.serve_forever()


@click.command()
@click.option(
    "--crash-bin",
    "--crash_bin",
    "-c",
    help="filename to serialize crash bin class to",
    default="boofuzz-crash-bin",
    metavar="FILENAME",
)
@click.option(
    "--ignore-pid",
    "--ignore_pid",
    "-i",
    type=int,
    help="PID to ignore when searching for target process",
    metavar="PID",
)
@click.option(
    "--log-level",
    "--log_level",
    "-l",
    help="log level: default 1, increase for more verbosity",
    type=int,
    default=1,
    metavar="LEVEL",
)
@click.option("--proc-name", "--proc_name", "-p", help="process name to search for and attach to", metavar="NAME")
@click.option("--port", "-P", help="TCP port to bind this agent to", type=int, default=DEFAULT_PROCMON_PORT)
@click.option("--ip", "-I", help="Listen on this IP for incoming connections from boofuzz", type=str, default="127.0.0.1")
def go(crash_bin, ignore_pid, log_level, proc_name, port, ip):
    serve_procmon(ip, port=port, crash_bin=crash_bin, proc_name=proc_name, ignore_pid=ignore_pid, log_level=log_level)


if __name__ == "__main__":
    go()
