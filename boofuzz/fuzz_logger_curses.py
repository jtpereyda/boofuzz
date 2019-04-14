from __future__ import division
import os
import time
import curses
import threading

from . import helpers
from . import ifuzz_logger_backend


DEFAULT_HEX_TO_STR = helpers.hex_to_hexstr


class FuzzLoggerCurses(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for a console GUI using curses. This hasn't been tested on Windows.
    """

    def __init__(self,
                 web_port=26000,
                 window_height=40,
                 window_width=130,
                 auto_scoll=True,
                 max_log_lines=200,
                 wait_on_quit=True,
                 bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        :type web_port: int
        :param web_port: Webinterface port

        :type window_height: int
        :param window_height: Default console heigth, set to on startup

        :type window_width: int
        :param window_width: Default console width, set to on startup

        :type auto_scoll: bool
        :param auto_scoll: Whether to auto-scoll the cases and crashed windows to allways display the last line if there
                           are too many lines to display all of them.

        :type max_log_lines: int
        :param max_log_lines: Maximum log lines to keep in the internal storage. Additional lines exceeding this limit
                              will not be displayed.

        :type wait_on_quit: bool
        :param wait_on_quit: Whether to keep the GUI open and wait for user-input when the main thread is about to exit.

        :type bytes_to_str: function
        :param bytes_to_str: Function that converts sent/received bytes data to string for logging.
        """
        self._title = "boofuzz"
        self._web_port = web_port
        self._max_log_lines = max_log_lines
        self._auto_scroll = auto_scoll
        self._current_data = None
        self._log_storage = []
        self._fail_storage = []
        self._wait_on_quit = wait_on_quit
        self._quit = False
        self._status = 0  # 0: Running 1: Paused 2: Done
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

        # Resize console
        print("\x1b[8;{};{}t".format(window_height, window_width))
        self._height, self._width = window_height, window_width
        self._min_size_ok = True

        self._stdscr = curses.initscr()
        curses.start_color()
        curses.noecho()
        curses.curs_set(0)
        self._stdscr.nodelay(1)

        # Curses color pairs
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_WHITE)

        self._draw_thread = threading.Thread(name="curses_logger", target=self._draw_screen)
        self._draw_thread.start()

    def _thread_draw(self):
        curses.wrapper(self._draw_screen())

    def open_test_case(self, test_case_id, name, index, *args, **kwargs):
        self._log_storage = []
        self._total_index = index
        self._total_num_mutations = kwargs["num_mutations"]
        self._current_name = name
        self._current_index = kwargs["current_index"]
        self._current_num_mutations = kwargs["current_num_mutations"]
        self._log_storage.append(helpers.format_log_msg(msg_type='test_case', description=test_case_id,
                                                        format_type='curses'))
        self._event_log = True

    def open_test_step(self, description):
        self._log_storage.append(helpers.format_log_msg(msg_type='step', description=description,
                                                        format_type='curses'))
        self._event_log = True

    def log_info(self, description):
        self._log_storage.append(helpers.format_log_msg(msg_type='info', description=description,
                                                        format_type='curses'))
        self._event_log = True

    def log_check(self, description):
        self._log_storage.append(helpers.format_log_msg(msg_type='check', description=description,
                                                        format_type='curses'))
        self._event_log = True

    def log_pass(self, description=""):
        self._log_storage.append(helpers.format_log_msg(msg_type='pass', description=description,
                                                        format_type='curses'))
        self._event_log = True

    def log_fail(self, description=""):
        self._fail_storage.append([self._total_index, description])
        self._log_storage.append(helpers.format_log_msg(msg_type='fail', description=description,
                                                        format_type='curses'))
        self._event_crash = True

    def log_error(self, description):
        self._log_storage.append(helpers.format_log_msg(msg_type='error', description=description,
                                                        format_type='curses'))
        self._event_log = True

    def log_recv(self, data):
        self._log_storage.append(helpers.format_log_msg(msg_type='recv', data=data,
                                                        format_type='curses'))
        self._event_log = True

    def log_send(self, data):
        self._log_storage.append(helpers.format_log_msg(msg_type='send', data=data,
                                                        format_type='curses'))
        self._event_log = True

    def close_test_case(self):
        self._event_case_close = True

    def close_test(self):
        self._status = 2
        self._quit = True
        self._draw_thread.join()
        curses.nocbreak()
        self._stdscr.keypad(False)
        curses.echo()
        curses.endwin()

    def window_resize(self):
        self._event_resize = True

    def _draw_main(self):
        # TODO: Fix bug with wrong window size on first startup
        self._height, self._width = os.popen('stty size', 'r').read().split()
        # columns, rows = os.get_terminal_size() for python 3
        self._height = int(self._height)
        self._width = int(self._width)
        curses.resizeterm(self._height, self._width)
        self._stdscr.erase()
        if self._height < 40 or self._width < 130:
            self._min_size_ok = False
            return
        else:
            self._min_size_ok = True

        # Render title
        self._stdscr.addstr(0, 0, '=' * self._width)
        start_x_title = int((self._width // 2) - (len(self._title) // 2) - len(self._title) % 2)
        self._stdscr.addstr(0, start_x_title, self._title, curses.color_pair(2) | curses.A_BOLD)

        # Render status bar
        self._stdscr.attron(curses.color_pair(7))
        self._stdscr.addstr(self._height - 1, 0, ' ' * (self._width - 1))
        self._stdscr.insch(' ')  # Fill bottom right corner
        if self._quit:
            self._stdscr.addstr(self._height - 1, 1, "Press 'q' to quit", curses.color_pair(7) | curses.A_BLINK)
        else:
            self._stdscr.addstr(self._height - 1, 1, "Press 'CTRL+C' to abort")
        self._stdscr.addstr(self._height - 1, self._width - len(self._version) - 1, self._version)
        self._stdscr.attroff(curses.color_pair(7))
        self._stdscr.refresh()

        # Initialise test case window
        # TODO: Handle lines longer than window width
        self._casescr_frame = curses.newpad(self._max_log_lines + 1, self._width)
        self._casescr_frame.nodelay(1)
        self._casescr_frame.border(0, 0, 0, " ", 0, 0, curses.ACS_VLINE, curses.ACS_VLINE)
        self._casescr_frame.addstr(0, 1, "Test case log", curses.color_pair(4) | curses.A_BOLD)
        self._casescr_frame.refresh(0, 0, 1, 0, self._height - 18, self._width)
        self._casescr = self._casescr_frame.subpad(self._max_log_lines, self._width - 2, 1, 1)
        self._draw_case()

        # Initialise crash window
        # TODO: Handle lines longer than window width
        self._crashescr_frame = curses.newpad(self._max_log_lines + 1, self._width)
        self._crashescr_frame.nodelay(1)
        self._crashescr_frame.border(0, 0, 0, " ", 0, 0, curses.ACS_VLINE, curses.ACS_VLINE)
        self._crashescr_frame.addstr(0, 1, "Crashes", curses.color_pair(3) | curses.A_BOLD)
        self._crashescr_frame.refresh(0, 0, self._height - 17, 0, self._height - 8, self._width)
        self._crashescr = self._crashescr_frame.subpad(self._max_log_lines, self._width - 2, 1, 1)
        self._draw_crash()

        # Initialise status window
        self._statscr = curses.newwin(6, self._width, self._height - 7, 0)
        self._statscr.nodelay(1)
        self._statscr.border()
        self._statscr.addstr(0, 1, "Status", curses.color_pair(2) | curses.A_BOLD)
        self._draw_stat()

    def _draw_case(self):
        # Test Case Screen
        pos = 0
        self._casescr.erase()
        for i in range(len(self._log_storage[:self._max_log_lines])):
            self._casescr.addnstr(i, 0, self._log_storage[i][0], self._width - 2,
                                  curses.color_pair(self._log_storage[i][1]))
            if i >= self._height - 19 and self._auto_scroll:
                pos += 1
        self._casescr.refresh(pos, 0, 2, 1, self._height - 18, self._width - 2)

    def _draw_crash(self):
        # Crashes Screen
        pos = 0
        for i in range(len(self._fail_storage[:self._max_log_lines])):
            self._crashescr.addstr(i, 0, "# " + str(self._fail_storage[i][0]), curses.color_pair(3))
            self._crashescr.addnstr(i, 9, self._fail_storage[i][1], self._width - 12)
            if i >= 9 and self._auto_scroll:
                pos += 1
        self._crashescr.refresh(pos, 0, self._height - 16, 1, self._height - 8, self._width - 2)

    def _draw_stat(self):
        # Status Screen
        self._indent_size = 16
        self._statscr.addstr(1, 1, "Webinterface:")
        self._statscr.addstr(1, self._indent_size, "localhost:{}".format(self._web_port))
        self._statscr.addstr(2, 1, "Case:")
        self._statscr.addstr(2, self._indent_size, _progess_bar(self._current_index,
                                                                self._current_num_mutations,
                                                                self._width - self._indent_size))
        self._statscr.addstr(3, 1, "Total:")
        self._statscr.addstr(3, self._indent_size, _progess_bar(self._total_index,
                                                                self._total_num_mutations,
                                                                self._width - self._indent_size))
        # TODO: Get paused flag from sessions
        if self._status == 0:
            self._statscr.addstr(4, 1, "Status:")
            self._statscr.addstr(4, self._indent_size, "Running", curses.color_pair(4))
        elif self._status == 1:
            self._statscr.addstr(4, 1, "Status:")
            self._statscr.addstr(4, self._indent_size, "Paused ", curses.color_pair(3) | curses.A_BLINK)
        elif self._status == 2:
            self._statscr.addstr(4, 1, "Status:")
            self._statscr.addstr(4, self._indent_size, "Done   ", curses.color_pair(5))

        self._statscr.refresh()

    def _draw_screen(self):
        k = 0
        wait_for_key = False
        try:
            while not ((k == ord('q') or not self._wait_on_quit) and self._quit):
                if self._event_resize:
                    self._draw_main()
                    self._event_resize = False

                if self._quit and not wait_for_key:
                    self._draw_main()
                    wait_for_key = True

                if self._min_size_ok:
                    if self._event_crash:
                        self._draw_crash()
                        self._event_crash = False

                    if self._event_log:
                        self._draw_case()
                        self._event_log = False

                    if self._event_case_close:
                        self._draw_stat()
                        self._event_case_close = False

                k = self._stdscr.getch()
                curses.flushinp()

                time.sleep(0.1)
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
