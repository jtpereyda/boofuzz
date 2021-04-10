#!/usr/bin/env python
from __future__ import print_function

import logging
import shlex
import time

import click

from . import constants, sessions
from .cli_context import CliContext
from .constants import DEFAULT_PROCMON_PORT
from .connections import TCPSocketConnection
from .fuzz_logger_csv import FuzzLoggerCsv
from .fuzz_logger_curses import FuzzLoggerCurses
from .fuzz_logger_text import FuzzLoggerText
from .helpers import parse_target
from .monitors import ProcessMonitor
from .utils.process_monitor_local import ProcessMonitorLocal
from .utils.debugger_thread_simple import DebuggerThreadSimple

temp_static_session = None
temp_static_procmon = None
temp_static_fuzz_only_one_case = None


@click.group(help="boofuzz experimental CLI; usage may change over time")
def cli():
    pass


@cli.group(help="Must be run via a fuzz script")
@click.option("--target", metavar="HOST:PORT", help="Target network address", required=True)
@click.option("--test-case-index", help="Test case index", type=str)
@click.option("--test-case-name", help="Name of node or specific test case")
@click.option("--csv-out", help="Output to CSV file")
@click.option(
    "--sleep-between-cases", help="Wait FLOAT (seconds) between test cases (partial seconds OK)", type=float, default=0
)
@click.option("--procmon-host", help="Process monitor port host or IP")
@click.option("--procmon-port", type=int, default=DEFAULT_PROCMON_PORT, help="Process monitor port")
@click.option("--procmon-start", help="Process monitor start command")
@click.option("--procmon-capture", is_flag=True, help="Capture stdout/stderr from target process upon failure")
@click.option("--tui/--no-tui", help="Enable/disable TUI")
@click.option("--text-dump/--no-text-dump", help="Enable/disable full text dump of logs", default=False)
@click.option("--feature-check", is_flag=True, help="Run a feature check instead of a fuzz test", default=False)
@click.option("--target-cmd", help="Target command and arguments")
@click.option(
    "--keep-web/--no-keep-web",
    is_flag=True,
    default=True,
    help="Keep web server for web UI open when out of fuzz cases",
)
@click.option(
    "--combinatorial/--no-combinatorial", is_flag=True, default=True, help="Enable fuzzing with multiple mutations"
)
@click.option(
    "--record-passes",
    default=10,
    type=int,
    help="Record this many cases before each failure. Set to 0 to record all test cases (high disk space usage!).",
)
@click.pass_context
def fuzz(
    ctx,
    target,
    test_case_index,
    test_case_name,
    csv_out,
    sleep_between_cases,
    procmon_host,
    procmon_port,
    procmon_start,
    procmon_capture,
    tui,
    text_dump,
    feature_check,
    target_cmd,
    keep_web,
    combinatorial,
    record_passes,
):
    local_procmon = None
    if target_cmd is not None and procmon_host is None:
        local_procmon = ProcessMonitorLocal(
            crash_filename="boofuzz-crash-bin",
            proc_name=None,
            pid_to_ignore=None,
            debugger_class=DebuggerThreadSimple,
            level=1,
        )

    fuzz_loggers = []
    if text_dump:
        fuzz_loggers.append(FuzzLoggerText())
    elif tui:
        fuzz_loggers.append(FuzzLoggerCurses())
    if csv_out is not None:
        f = open("boofuzz.csv", "wb")
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    procmon_options = {}
    if procmon_start is not None:
        procmon_options["start_commands"] = [procmon_start]
    if target_cmd is not None:
        procmon_options["start_commands"] = shlex.split(target_cmd)
    if procmon_capture:
        procmon_options["capture_output"] = True

    if local_procmon is not None or procmon_host is not None:
        if procmon_host is not None:
            procmon = ProcessMonitor(procmon_host, procmon_port)
        else:
            procmon = local_procmon
        procmon.set_options(**procmon_options)
        monitors = [procmon]
    else:
        procmon = None
        monitors = []

    if combinatorial:
        max_depth = None
    else:
        max_depth = 1

    if test_case_index is None:
        start = 1
        end = None
    elif "-" in test_case_index:
        start, end = test_case_index.split("-")
        if not start:
            start = 1
        else:
            start = int(start)
        if not end:
            end = None
        else:
            end = int(end)
    else:
        start = end = int(test_case_index)

    connection = TCPSocketConnection(*parse_target(target_name=target))

    session = sessions.Session(
        target=sessions.Target(
            connection=connection,
            monitors=monitors,
        ),
        fuzz_loggers=fuzz_loggers,
        sleep_time=sleep_between_cases,
        index_start=start,
        index_end=end,
        keep_web_open=keep_web,
        fuzz_db_keep_only_n_pass_cases=record_passes,
    )

    ctx.obj = CliContext(session=session)

    # The resultcallback is called after any subcommands, e.g. the one provided by the user
    @fuzz.resultcallback()
    def fuzzcallback(result, *args, **kwargs):
        if feature_check:
            session.feature_check()
        else:
            session.fuzz(name=test_case_name, max_depth=max_depth)

        if procmon is not None:
            procmon.stop_target()


@cli.command(name="open")
@click.option("--debug", help="Print debug info to console", is_flag=True)
@click.option(
    "--ui-port",
    help="Port on which to serve the web interface (default {0})".format(constants.DEFAULT_PROCMON_PORT),
    type=int,
    default=constants.DEFAULT_WEB_UI_PORT,
)
@click.option(
    "--ui-addr",
    help="Address on which to serve the web interface (default localhost). Set to empty "
    "string to serve on all interfaces.",
    type=str,
    default="localhost",
)
@click.argument("filename")
def open_file(debug, filename, ui_port, ui_addr):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    sessions.open_test_run(db_filename=filename, port=ui_port, address=ui_addr)

    print("Serving web page at http://{0}:{1}. Hit Ctrl+C to quit.".format(ui_addr, ui_port))
    while True:
        time.sleep(0.001)


def main():
    cli()


def main_helper(click_command=None):
    """
    Args:
        click_command (click.Command): Click command to add as a sub-command to boo fuzz.
    """
    if click_command is not None:
        fuzz.add_command(click_command)
    main()


if __name__ == "__main__":
    main()
