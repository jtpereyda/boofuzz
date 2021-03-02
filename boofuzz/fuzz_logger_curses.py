from __future__ import division

import atexit
import sys
import time
import warnings

from six import StringIO

try:
    import curses  # pytype: disable=import-error
except ImportError:
    # Allow fuzz_logger_curses to be imported on Windows -- will fail if you try to use it.
    warnings.warn("Importing curses failed. Optional console GUI features will not be available.", UserWarning)
    curses = None

import signal
import threading

from math import *
from . import helpers
from . import ifuzz_logger_backend

if sys.version_info >= (3, 3):
    from shutil import get_terminal_size
else:
    try:
        from shutil_backports import get_terminal_size
    except ImportError:
        # Allow fuzz_logger_curses to be imported when shutil_backports is not available for install. Will fallback to a
        # static-sized console window, but warn the user so they can correct the issue.
        def get_terminal_size():
            return [130, 40]

        warnings.warn("Console GUI will not resize properly. Install shutil_backports for full support.", UserWarning)

COLOR_PAIR_WHITE = 1
COLOR_PAIR_CYAN = 2
COLOR_PAIR_RED = 3
COLOR_PAIR_YELLOW = 4
COLOR_PAIR_GREEN = 5
COLOR_PAIR_MAGENTA = 6
COLOR_PAIR_BLACK = 7

STATUS_RUNNING = 0
STATUS_PAUSED = 1
STATUS_DONE = 2


class FuzzLoggerCurses(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for a console GUI using curses. This hasn't been tested on Windows.
    """

    INDENT_SIZE = 2

    def __init__(
        self,
        web_port=26000,
        window_height=40,
        window_width=130,
        auto_scroll=True,
        max_log_lines=500,
        wait_on_quit=True,
        min_refresh_rate=1000,
        bytes_to_str=helpers.hex_to_hexstr,
    ):
        """
        :type web_port: int
        :param web_port: Webinterface port. Default 26000

        :type window_height: int
        :param window_height: Default console height, set to on startup. Default 40

        :type window_width: int
        :param window_width: Default console width, set to on startup. Default 130

        :type auto_scroll: bool
        :param auto_scroll: Whether to auto-scroll the cases and crashed windows to always display the last line if
                            there are too many lines to display all of them. Default True

        :type max_log_lines: int
        :param max_log_lines: Maximum log lines to keep in the internal storage. Additional lines exceeding this limit
                              will not be displayed. Default 500

        :type wait_on_quit: bool
        :param wait_on_quit: Whether to keep the GUI open and wait for user-input when the main thread is about to exit.
                             Default True

        :type min_refresh_rate: int
        :param min_refresh_rate: The delay between two checks for a resize of the terminal in milliseconds.
                                 Increment 100 ms. Default 1000 ms

        :type bytes_to_str: function
        :param bytes_to_str: Function that converts sent/received bytes data to string for logging.
        """

        self._title = "boofuzz"
        self._web_port = web_port
        self._max_log_lines = max_log_lines
        self._auto_scroll = auto_scroll
        self._current_data = None
        self._log_storage = []
        self._fail_storage = []
        self._wait_on_quit = wait_on_quit
        self._quit = False
        self._status = STATUS_RUNNING
        self._refresh_interval = min_refresh_rate
        self._event_resize = True
        self._event_log = False
        self._event_case_close = False
        self._event_crash = False

        self._total_index = 0
        self._total_num_mutations = 0
        self._current_name = ""
        self._current_index = 0
        self._current_num_mutations = 0

        self._format_raw_bytes = bytes_to_str
        self._version = helpers.get_boofuzz_version(helpers)

        # Resize console to minimum size
        self._width, self._height = get_terminal_size()
        if self._height < window_height or self._width < window_width:
            print("\x1b[8;{};{}t".format(window_height, window_width))
            self._height, self._width = window_height, window_width
        self._height_old = 0
        self._width_old = 0
        self._min_size_ok = True

        sys.stdout = sys.stderr = self._std_buffer = StringIO()
        atexit.register(self._cleanup)

        self._stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.noecho()
        curses.curs_set(0)
        self._stdscr.nodelay(True)

        # Curses color pairs
        curses.init_pair(COLOR_PAIR_WHITE, curses.COLOR_WHITE, -1)
        curses.init_pair(COLOR_PAIR_CYAN, curses.COLOR_CYAN, -1)
        curses.init_pair(COLOR_PAIR_RED, curses.COLOR_RED, -1)
        curses.init_pair(COLOR_PAIR_YELLOW, curses.COLOR_YELLOW, -1)
        curses.init_pair(COLOR_PAIR_GREEN, curses.COLOR_GREEN, -1)
        curses.init_pair(COLOR_PAIR_MAGENTA, curses.COLOR_MAGENTA, -1)
        curses.init_pair(COLOR_PAIR_BLACK, curses.COLOR_BLACK, curses.COLOR_WHITE)

        # Start thread and restore the original SIGWINCH handler
        self._draw_thread = threading.Thread(name="curses_logger", target=self._draw_screen)
        self._draw_thread.setDaemon(True)
        current_signal_handler = signal.getsignal(signal.SIGWINCH)
        self._draw_thread.start()
        signal.signal(signal.SIGWINCH, current_signal_handler)

    def _cleanup(self):
        self._wait_on_quit = False
        self.close_test()
        sys.stderr = sys.__stderr__
        sys.stdout = sys.__stdout__
        print(self._std_buffer.getvalue())
        self._std_buffer.close()

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._log_storage = []
        self._current_name = name
        self._total_index = index
        if "current_index" in kwargs:
            self._current_index = kwargs["current_index"]
        if "current_num_mutations" in kwargs:
            self._current_num_mutations = kwargs["current_num_mutations"]
        if "num_mutations" in kwargs:
            self._total_num_mutations = kwargs["num_mutations"]

        self._log_storage.append(
            helpers.format_log_msg(msg_type="test_case", description=test_case_id, format_type="curses")
        )
        self._event_log = True

    def open_test_step(self, description):
        self._log_storage.append(helpers.format_log_msg(msg_type="step", description=description, format_type="curses"))
        self._event_log = True

    def log_info(self, description):
        self._log_storage.append(helpers.format_log_msg(msg_type="info", description=description, format_type="curses"))
        self._event_log = True

    def log_check(self, description):
        self._log_storage.append(
            helpers.format_log_msg(msg_type="check", description=description, format_type="curses")
        )
        self._event_log = True

    def log_pass(self, description=""):
        self._log_storage.append(helpers.format_log_msg(msg_type="pass", description=description, format_type="curses"))
        self._event_log = True

    def log_fail(self, description="", indent_size=INDENT_SIZE):
        # TODO: Why do some fail messages have a trailing whitespace?
        fail_msg = (
            "#"
            + str(self._total_index)
            + (4 * indent_size + 1 - len(str(self._total_index))) * " "
            + description.strip()
        )
        self._fail_storage.append([fail_msg.replace("\n", " "), COLOR_PAIR_WHITE])
        self._log_storage.append(helpers.format_log_msg(msg_type="fail", description=description, format_type="curses"))
        self._event_crash = True
        self._event_log = True

    def log_error(self, description="", indent_size=INDENT_SIZE):
        fail_msg = (
            "#"
            + str(self._total_index)
            + (4 * indent_size + 1 - len(str(self._total_index))) * " "
            + description.strip()
        )
        self._fail_storage.append([fail_msg.replace("\n", " "), COLOR_PAIR_RED])
        self._log_storage.append(
            helpers.format_log_msg(msg_type="error", description=description, format_type="curses")
        )
        self._event_crash = True
        self._event_log = True

    def log_recv(self, data):
        self._log_storage.append(helpers.format_log_msg(msg_type="receive", data=data, format_type="curses"))
        self._event_log = True

    def log_send(self, data):
        self._log_storage.append(helpers.format_log_msg(msg_type="send", data=data, format_type="curses"))
        self._event_log = True

    def close_test_case(self):
        self._event_case_close = True

    def close_test(self):
        self._status = STATUS_DONE
        self._quit = True
        try:
            if self._wait_on_quit:
                self._draw_thread.join()
            else:
                self._draw_thread.join(max(0.2, self._refresh_interval * 3))
        except KeyboardInterrupt:
            pass
        finally:
            self._wait_on_quit = False
            curses.nocbreak()
            self._stdscr.keypad(False)
            curses.echo()
            curses.endwin()

    def _draw_main(self, force=False):
        self._width, self._height = get_terminal_size()
        if not force and self._width == self._width_old and self._height == self._height_old:
            return
        self._height_old = self._height
        self._width_old = self._width
        curses.resizeterm(self._height, self._width)
        self._stdscr.erase()
        if self._height < 40 or self._width < 130:
            self._min_size_ok = False
            return
        else:
            self._min_size_ok = True

        # Render title
        self._stdscr.addstr(0, 0, "=" * self._width)
        start_x_title = int((self._width // 2) - (len(self._title) // 2) - len(self._title) % 2)
        self._stdscr.addstr(0, start_x_title, self._title, curses.color_pair(COLOR_PAIR_CYAN) | curses.A_BOLD)

        # Render status bar
        self._stdscr.attron(curses.color_pair(COLOR_PAIR_BLACK))
        self._stdscr.addstr(self._height - 1, 0, " " * (self._width - 1))
        self._stdscr.insch(" ")  # Fill bottom right corner
        if self._quit:
            self._stdscr.addstr(
                self._height - 1, 1, "Press 'q' to quit", curses.color_pair(COLOR_PAIR_BLACK) | curses.A_BLINK
            )
        else:
            self._stdscr.addstr(self._height - 1, 1, "Press 'CTRL+C' to abort")
        self._stdscr.addstr(self._height - 1, self._width - len(self._version) - 1, self._version)
        self._stdscr.attroff(curses.color_pair(COLOR_PAIR_BLACK))
        self._stdscr.refresh()

        # Initialise test case window
        self._casescr_frame = curses.newpad(self._max_log_lines + 1, self._width)
        self._casescr_frame.nodelay(True)
        self._casescr_frame.border()
        self._casescr_frame.addstr(0, 1, "Test case log", curses.color_pair(COLOR_PAIR_YELLOW) | curses.A_BOLD)
        self._casescr_frame.refresh(0, 0, 1, 0, self._height - 18, self._width)
        self._casescr = self._casescr_frame.subpad(self._max_log_lines, self._width - 2, 1, 1)
        self._draw_case()

        # Initialise crash window
        self._crashescr_frame = curses.newpad(self._max_log_lines + 1, self._width)
        self._crashescr_frame.nodelay(True)
        self._crashescr_frame.border()
        self._crashescr_frame.addstr(0, 1, "Crashes", curses.color_pair(COLOR_PAIR_RED) | curses.A_BOLD)
        self._crashescr_frame.refresh(0, 0, self._height - 17, 0, self._height - 8, self._width)
        self._crashescr = self._crashescr_frame.subpad(self._max_log_lines, self._width - 2, 1, 1)
        self._draw_crash()

        # Initialise status window
        self._statscr = curses.newwin(6, self._width, self._height - 7, 0)
        self._statscr.nodelay(True)
        self._statscr.border()
        self._statscr.addstr(0, 1, "Status", curses.color_pair(COLOR_PAIR_CYAN) | curses.A_BOLD)
        self._draw_stat()

    def _draw_case(self, indent_size=INDENT_SIZE):
        # Test Case Screen
        # TODO: Handle longer indent for multi-line 'fail' messages
        self._casescr.erase()
        total_indent_size = indent_size * 2 + 1 + 25

        _render_pad(
            lines=self._log_storage[: self._max_log_lines],
            pad=self._casescr,
            y_min=2,
            x_min=1,
            y_max=self._height - 18,
            x_max=self._width - 1,
            max_lines=self._max_log_lines,
            total_indent_size=total_indent_size,
            auto_scroll=self._auto_scroll,
        )

    def _draw_crash(self, indent_size=INDENT_SIZE):
        # Crashes Screen
        total_indent_size = indent_size * 5

        _render_pad(
            lines=self._fail_storage[: self._max_log_lines],
            pad=self._crashescr,
            y_min=self._height - 16,
            x_min=1,
            y_max=self._height - 8,
            x_max=self._width - 1,
            max_lines=self._max_log_lines,
            total_indent_size=total_indent_size,
            auto_scroll=self._auto_scroll,
            truncate_long_lines=True,
        )

    def _draw_stat(self):
        # Status Screen
        self._indent_size = 16
        self._statscr.addstr(1, 1, "Webinterface:")
        self._statscr.addstr(1, self._indent_size, "localhost:{}".format(self._web_port))
        self._statscr.addstr(2, 1, "Case:")
        # fmt: off
        self._statscr.addstr(2, self._indent_size, _progess_bar(self._current_index,
                                                                self._current_num_mutations,
                                                                self._width - self._indent_size))
        self._statscr.addstr(3, 1, "Total:")
        self._statscr.addstr(3, self._indent_size, _progess_bar(self._total_index,
                                                                self._total_num_mutations,
                                                                self._width - self._indent_size))
        # fmt: on
        # TODO: Get paused flag from sessions
        if self._status == STATUS_RUNNING:
            self._statscr.addstr(4, 1, "Status:")
            self._statscr.addstr(4, self._indent_size, "Running", curses.color_pair(COLOR_PAIR_YELLOW))
        elif self._status == STATUS_PAUSED:
            self._statscr.addstr(4, 1, "Status:")
            self._statscr.addstr(4, self._indent_size, "Paused ", curses.color_pair(COLOR_PAIR_RED) | curses.A_BLINK)
        elif self._status == STATUS_DONE:
            self._statscr.addstr(4, 1, "Status:")
            self._statscr.addstr(4, self._indent_size, "Done   ", curses.color_pair(COLOR_PAIR_GREEN))

        self._statscr.refresh()

    def _draw_screen(self):
        error_counter = 0
        ms_since_refresh = 0
        key = 0
        wait_for_key = False
        try:
            while not ((key == ord("q") or not self._wait_on_quit) and self._quit):
                try:
                    if self._event_resize or ms_since_refresh >= self._refresh_interval:
                        self._draw_main()
                        ms_since_refresh = 0
                        self._event_resize = False

                    if self._quit and not wait_for_key:
                        self._draw_main(force=True)
                        wait_for_key = True

                    if self._min_size_ok:
                        if self._event_log:
                            self._draw_case()
                            self._event_log = False

                        if self._event_crash:
                            self._draw_crash()
                            self._event_crash = False

                        if self._event_case_close:
                            self._draw_stat()
                            self._event_case_close = False

                    key = self._stdscr.getch()
                    curses.flushinp()

                    time.sleep(0.1)
                    ms_since_refresh += 100
                    error_counter = 0
                except curses.error:
                    error_counter += 1
                    if error_counter > 2:
                        raise
        finally:
            curses.nocbreak()
            self._stdscr.keypad(False)
            curses.echo()
            curses.endwin()


def _progess_bar(current, total, width):
    try:
        percent = current / total
    except ZeroDivisionError:
        percent = 0
    title_str = "{:7d} of {:7d} ".format(current, total)
    percent_str = " {:7.3f}%".format(percent * 100)
    bar_len = width - 4 - len(title_str) - len(percent_str)
    num_bars = int(round(percent * bar_len))
    bar_str = "[" + "=" * num_bars + " " * (bar_len - num_bars) + "]"
    return title_str + bar_str + percent_str


def _render_pad(
    lines, pad, y_min, x_min, y_max, x_max, max_lines, total_indent_size, auto_scroll, truncate_long_lines=False
):
    total_rows = 0
    height = y_max - y_min + 1
    width = x_max - x_min

    for i in range(len(lines)):
        if total_rows < max_lines - 1:
            pad.addnstr(total_rows, 0, lines[i][0], width, curses.color_pair(lines[i][1]))
            total_rows += 1
        else:
            pad.addstr(
                total_rows,
                0,
                "Maximum number of lines reached for this window! Increase 'max_log_lines'",
                curses.color_pair(COLOR_PAIR_RED),
            )
            total_rows += 1
            break

        if not truncate_long_lines:
            columns = width - total_indent_size
            rows = int(ceil(len(lines[i][0][width:]) / columns))
            if rows >= 1:
                for row in range(1, rows + 1):
                    if total_rows < max_lines - 1:
                        pad.addstr(
                            total_rows,
                            total_indent_size,
                            lines[i][0][width:][(row * columns) - columns : row * columns],
                            curses.color_pair(lines[i][1]),
                        )
                        total_rows += 1
                    else:
                        break

    if total_rows > height and auto_scroll:
        offset = total_rows - height
        pad.refresh(offset, 0, y_min, x_min, y_max, x_max)
    else:
        pad.refresh(0, 0, y_min, x_min, y_max, x_max)
