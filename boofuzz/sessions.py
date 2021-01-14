from __future__ import absolute_import, print_function

import datetime
import errno
import logging
import os
import pickle
import re
import socket
import threading
import time
import traceback
import warnings
import zlib
from builtins import input
from io import open

import six
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer

from boofuzz import (
    blocks,
    constants,
    event_hook,
    exception,
    fuzz_logger,
    fuzz_logger_curses,
    fuzz_logger_db,
    fuzz_logger_text,
    helpers,
    pgraph,
    primitives,
)
from boofuzz.monitors import CallbackMonitor
from boofuzz.mutation import Mutation
from boofuzz.mutation_context import MutationContext
from boofuzz.protocol_session import ProtocolSession
from boofuzz.web.app import app
from .exception import BoofuzzFailure


class Target(object):
    """Target descriptor container.

    Takes an ITargetConnection and wraps send/recv with appropriate
    FuzzDataLogger calls.

    Encapsulates pedrpc connection logic.

    Contains a logger which is configured by Session.add_target().

    Example:
        tcp_target = Target(SocketConnection(host='127.0.0.1', port=17971))

    Args:
        connection (itarget_connection.ITargetConnection): Connection to system under test.
        monitors (List[Union[IMonitor, pedrpc.Client]]): List of Monitors for this Target.
        monitor_alive: List of Functions that are called when a Monitor is alive. It is passed
                          the monitor instance that became alive. Use it to e.g. set options
                          on restart.
        repeater (repeater.Repeater): Repeater to use for sending. Default None.
        procmon: Deprecated interface for adding a process monitor.
        procmon_options: Deprecated interface for adding a process monitor.

    """

    def __init__(
        self,
        connection,
        monitors=None,
        monitor_alive=None,
        max_recv_bytes=10000,
        repeater=None,
        procmon=None,
        procmon_options=None,
        **kwargs
    ):
        self._fuzz_data_logger = None

        self._target_connection = connection
        self.max_recv_bytes = max_recv_bytes
        self.repeater = repeater
        self.monitors = monitors if monitors is not None else []
        if procmon is not None:
            if procmon_options is not None:
                procmon.set_options(**procmon_options)
            self.monitors.append(procmon)

        self.monitor_alive = monitor_alive if monitor_alive is not None else []

        if "procmon" in kwargs.keys() and kwargs["procmon"] is not None:
            warnings.warn(
                "Target(procmon=...) is deprecated. Please change your code"
                " and add it to the monitors argument. For now, we do this "
                "for you, but this will be removed in the future.",
                FutureWarning,
            )
            self.monitors.append(kwargs["procmon"])

        if "netmon" in kwargs.keys() and kwargs["netmon"] is not None:
            warnings.warn(
                "Target(netmon=...) is deprecated. Please change your code"
                " and add it to the monitors argument. For now, we do this "
                "for you, but this will be removed in the future.",
                FutureWarning,
            )
            self.monitors.append(kwargs["netmon"])

        # set these manually once target is instantiated.
        self.vmcontrol = None
        self.vmcontrol_options = {}

    @property
    def netmon_options(self):
        raise NotImplementedError(
            "This property is not supported; grab netmon from monitors and use set_options(**dict)"
        )

    @property
    def procmon_options(self):
        raise NotImplementedError(
            "This property is not supported; grab procmon from monitors and use set_options(**dict)"
        )

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._fuzz_data_logger.log_info("Closing target connection...")
        self._target_connection.close()
        self._fuzz_data_logger.log_info("Connection closed.")

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._fuzz_data_logger.log_info("Opening target connection ({0})...".format(self._target_connection.info))
        self._target_connection.open()
        self._fuzz_data_logger.log_info("Connection opened.")

    def pedrpc_connect(self):
        warnings.warn(
            "pedrpc_connect has been renamed to monitors_alive. "
            "This alias will stop working in a future version of boofuzz.",
            FutureWarning,
        )

        return self.monitors_alive()

    def monitors_alive(self):
        """
        Wait for the monitors to become alive / establish connection to the RPC server.
        This method is called on every restart of the target and when it's added to a session.
        After successful probing, a callback is called, passing the monitor.

        :return: None
        """
        for monitor in self.monitors:
            while True:
                if monitor.alive():
                    break
                time.sleep(1)

            if self.monitor_alive:
                for cb in self.monitor_alive:
                    cb(monitor)

    def recv(self, max_bytes=None):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        if max_bytes is None:
            max_bytes = self.max_recv_bytes

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("Receiving...")

        data = self._target_connection.recv(max_bytes=max_bytes)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_recv(data)

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            None
        """
        num_sent = 0
        if self._fuzz_data_logger is not None:
            repeat = ""
            if self.repeater is not None:
                repeat = ", " + self.repeater.log_message()

            self._fuzz_data_logger.log_info("Sending {0} bytes{1}...".format(len(data), repeat))

        if self.repeater is not None:
            self.repeater.start()
            while self.repeater.repeat():
                num_sent = self._target_connection.send(data=data)
            self.repeater.reset()
        else:
            num_sent = self._target_connection.send(data=data)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_send(data[:num_sent])

    def set_fuzz_data_logger(self, fuzz_data_logger):
        """
        Set this object's fuzz data logger -- for sent and received fuzz data.

        :param fuzz_data_logger: New logger.
        :type fuzz_data_logger: ifuzz_logger.IFuzzLogger

        :return: None
        """
        self._fuzz_data_logger = fuzz_data_logger


class Connection(pgraph.Edge):
    def __init__(self, src, dst, callback=None):
        """
        Extends pgraph.edge with a callback option. This allows us to register a function to call between node
        transmissions to implement functionality such as challenge response systems. The callback method must follow
        this prototype::

            def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as sesson.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet.

        Args:
            src (int): Edge source ID
            dst (int): Edge destination ID
            callback (function): Optional. Callback function to pass received data to between node xmits
        """

        super(Connection, self).__init__(src, dst)

        self.callback = callback


class SessionInfo(object):
    def __init__(self, db_filename):
        self._db_reader = fuzz_logger_db.FuzzLoggerDbReader(db_filename=db_filename)

    @property
    def monitor_results(self):
        return self._db_reader.failure_map

    @property
    def monitor_data(self):
        return {-1, "Monitor Data is not currently saved in the database"}

    @property
    def procmon_results(self):
        warnings.warn(
            "procmon_results has been renamed to monitor_results."
            "This alias will stop working in a future version of boofuzz",
            FutureWarning,
        )
        return self.monitor_results

    @property
    def netmon_results(self):
        warnings.warn(
            "netmon_results is now part of monitor_data" "This alias will stop working in a future version of boofuzz",
            FutureWarning,
        )
        return self.monitor_data

    @property
    def fuzz_node(self):
        return None

    @property
    def total_num_mutations(self):
        return None

    @property
    def total_mutant_index(self):
        x = next(self._db_reader.query("SELECT COUNT(*) FROM cases"))[0]
        return x

    @property
    def mutant_index(self):
        return None

    def test_case_data(self, index):
        """Return test case data object (for use by web server)

        Args:
            index (int): Test case index

        Returns:
            Test case data object
        """
        return self._db_reader.get_test_case_data(index=index)

    @property
    def is_paused(self):
        return False

    @property
    def state(self):
        return "finished"


class WebApp(object):
    """Serve fuzz data over HTTP.

    Args:
        session_info (SessionInfo): Object providing information on session
        web_port (int):         Port for monitoring fuzzing campaign via a web browser. Default 26000.
    """

    def __init__(self, session_info, web_port=constants.DEFAULT_WEB_UI_PORT, web_addr="localhost"):
        self._session_info = session_info
        self._web_interface_thread = self._build_webapp_thread(port=web_port, address=web_addr)
        pass

    def _build_webapp_thread(self, port, address):
        app.session = self._session_info
        http_server = HTTPServer(WSGIContainer(app))
        http_server.listen(port, address=address)
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread

    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc."""
        if not self._web_interface_thread.is_alive():
            # spawn the web interface.
            self._web_interface_thread.start()


def open_test_run(db_filename, port=constants.DEFAULT_WEB_UI_PORT, address="localhost"):
    s = SessionInfo(db_filename=db_filename)
    w = WebApp(session_info=s, web_port=port, web_addr=address)
    w.server_init()


class Session(pgraph.Graph):
    """
    Extends pgraph.graph and provides a container for architecting protocol dialogs.

    Args:
        session_filename (str): Filename to serialize persistent data to. Default None.
        index_start (int);      First test case index to run
        index_end (int);        Last test case index to run
        sleep_time (float):     Time in seconds to sleep in between tests. Default 0.
        restart_interval (int): Restart the target after n test cases, disable by setting to 0 (default).
        console_gui (bool):     Use curses to generate a static console screen similar to the webinterface. Has not been
                                tested under Windows. Default False.
        crash_threshold_request (int):  Maximum number of crashes allowed before a request is exhausted. Default 12.
        crash_threshold_element (int):  Maximum number of crashes allowed before an element is exhausted. Default 3.
        restart_sleep_time (int): Time in seconds to sleep when target can't be restarted. Default 5.
        restart_callbacks (list of method): The registered method will be called after a failed post_test_case_callback
                                            Default None.
        restart_threshold (int):    Maximum number of retries on lost target connection. Default None (indefinitely).
        restart_timeout (float):    Time in seconds for that a connection attempt should be retried. Default None
                                    (indefinitely).
        pre_send_callbacks (list of method): The registered method will be called prior to each fuzz request.
                                            Default None.
        post_test_case_callbacks (list of method): The registered method will be called after each fuzz test case.
                                                  Default None.
        post_start_target_callbacks (list of method): Method(s) will be called after the target is started or restarted,
                                                      say, by a process monitor.
        web_port (int):         Port for monitoring fuzzing campaign via a web browser. Default 26000.
        keep_web_open (bool):     Keep the webinterface open after session completion. Default True.
        fuzz_loggers (list of ifuzz_logger.IFuzzLogger): For saving test data and results.. Default Log to STDOUT.
        fuzz_db_keep_only_n_pass_cases (int): Minimize disk usage by only saving passing test cases
                                              if they are in the n test cases preceding a failure or error.
                                              Set to 0 to save after every test case (high disk I/O!). Default 0.
        receive_data_after_each_request (bool): If True, Session will attempt to receive a reply after transmitting
                                                each non-fuzzed node. Default True.
        check_data_received_each_request (bool): If True, Session will verify that some data has
                                                 been received after transmitting each non-fuzzed node, and if not,
                                                 register a failure. If False, this check will not be performed. Default
                                                 False. A receive attempt is still made unless
                                                 receive_data_after_each_request is False.
        receive_data_after_fuzz (bool): If True, Session will attempt to receive a reply after transmitting
                                        a fuzzed message. Default False.
        ignore_connection_reset (bool): Log ECONNRESET errors ("Target connection reset") as "info" instead of
                                failures.
        ignore_connection_aborted (bool): Log ECONNABORTED errors as "info" instead of failures.
        ignore_connection_issues_when_sending_fuzz_data (bool): Ignore fuzz data transmission failures. Default True.
                                This is usually a helpful setting to enable, as targets may drop connections once a
                                message is clearly invalid.
        ignore_connection_ssl_errors (bool): Log SSL related errors as "info" instead of failures. Default False.
        reuse_target_connection (bool): If True, only use one target connection instead of reconnecting each test case.
                                        Default False.
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.
    """

    def __init__(
        self,
        session_filename=None,
        index_start=1,
        index_end=None,
        sleep_time=0.0,
        restart_interval=0,
        web_port=constants.DEFAULT_WEB_UI_PORT,
        keep_web_open=True,
        console_gui=False,
        crash_threshold_request=12,
        crash_threshold_element=3,
        restart_sleep_time=5,
        restart_callbacks=None,
        restart_threshold=None,
        restart_timeout=None,
        pre_send_callbacks=None,
        post_test_case_callbacks=None,
        post_start_target_callbacks=None,
        fuzz_loggers=None,
        fuzz_db_keep_only_n_pass_cases=0,
        receive_data_after_each_request=True,
        check_data_received_each_request=False,
        receive_data_after_fuzz=False,
        ignore_connection_reset=False,
        ignore_connection_aborted=False,
        ignore_connection_issues_when_sending_fuzz_data=True,
        ignore_connection_ssl_errors=False,
        reuse_target_connection=False,
        target=None,
    ):
        self._ignore_connection_reset = ignore_connection_reset
        self._ignore_connection_aborted = ignore_connection_aborted
        self._ignore_connection_issues_when_sending_fuzz_data = ignore_connection_issues_when_sending_fuzz_data
        self._reuse_target_connection = reuse_target_connection
        self._ignore_connection_ssl_errors = ignore_connection_ssl_errors

        super(Session, self).__init__()

        self.session_filename = session_filename
        self._index_start = max(index_start, 1)
        self._index_end = index_end
        self.sleep_time = sleep_time
        self.restart_interval = restart_interval
        self.web_port = web_port
        self._keep_web_open = keep_web_open
        self.console_gui = console_gui
        self._crash_threshold_node = crash_threshold_request
        self._crash_threshold_element = crash_threshold_element
        self.restart_sleep_time = restart_sleep_time
        self.restart_threshold = restart_threshold
        self.restart_timeout = restart_timeout
        if fuzz_loggers is None:
            fuzz_loggers = []
            if self.console_gui and os.name != "nt":
                fuzz_loggers.append(fuzz_logger_curses.FuzzLoggerCurses(web_port=self.web_port))
                self._keep_web_open = False
            else:
                fuzz_loggers = [fuzz_logger_text.FuzzLoggerText()]

        helpers.mkdir_safe(os.path.join(constants.RESULTS_DIR))
        self._run_id = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(":", "-")
        self._db_filename = os.path.join(constants.RESULTS_DIR, "run-{0}.db".format(self._run_id))
        self._db_logger = fuzz_logger_db.FuzzLoggerDb(
            db_filename=self._db_filename, num_log_cases=fuzz_db_keep_only_n_pass_cases
        )

        self._crash_filename = "boofuzz-crash-bin-{0}".format(self._run_id)

        self._fuzz_data_logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self._db_logger] + fuzz_loggers)
        self._check_data_received_each_request = check_data_received_each_request
        self._receive_data_after_each_request = receive_data_after_each_request
        self._receive_data_after_fuzz = receive_data_after_fuzz
        self._skip_current_node_after_current_test_case = False
        self._skip_current_element_after_current_test_case = False

        if self.web_port is not None:
            self.web_interface_thread = self.build_webapp_thread(port=self.web_port)

        if pre_send_callbacks is None:
            pre_send_methods = []
        else:
            pre_send_methods = pre_send_callbacks

        if post_test_case_callbacks is None:
            post_test_case_methods = []
        else:
            post_test_case_methods = post_test_case_callbacks

        if post_start_target_callbacks is None:
            post_start_target_methods = []
        else:
            post_start_target_methods = post_start_target_callbacks

        if restart_callbacks is None:
            restart_methods = []
        else:
            restart_methods = restart_callbacks

        self._callback_monitor = CallbackMonitor(
            on_pre_send=pre_send_methods,
            on_post_send=post_test_case_methods,
            on_restart_target=restart_methods,
            on_post_start_target=post_start_target_methods,
        )

        self.total_num_mutations = 0
        self.total_mutant_index = 0
        self.mutant_index = 0
        self.fuzz_node = None
        self.targets = []
        self.monitor_results = {}  # map of test case indices to list of crash synopsis strings (failed cases only)
        # map of test case indices to list of supplement captured data (all cases where data was captured)
        self.monitor_data = {}
        self.is_paused = False
        self.crashing_primitives = {}
        self.on_failure = event_hook.EventHook()

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root = pgraph.Node(name="__ROOT_NODE__")
        self.root.label = self.root.name
        self.last_recv = None
        self.last_send = None

        self.add_node(self.root)

        if target is not None:

            def apply_options(monitor):
                monitor.set_options(crash_filename=self._crash_filename)

                return

            target.monitor_alive.append(apply_options)

            try:
                self.add_target(target)
            except exception.BoofuzzRpcError as e:
                self._fuzz_data_logger.log_error(str(e))
                raise

    @property
    def netmon_results(self):
        raise NotImplementedError(
            "netmon_results is now part of monitor_results and thus can't be accessed directly."
            " Please update your code."
        )

    def add_node(self, node):
        """
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        Args:
            node (pgraph.Node): Node to add to session graph
        """

        node.number = len(self.nodes)
        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def add_target(self, target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target (Target): Target to add to session
        """

        # pass specified target parameters to the PED-RPC server.
        target.monitors_alive()
        target.set_fuzz_data_logger(fuzz_data_logger=self._fuzz_data_logger)

        if self._callback_monitor not in target.monitors:
            target.monitors.append(self._callback_monitor)

        # add target to internal list.
        self.targets.append(target)

    def connect(self, src, dst=None, callback=None):
        """
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. The session class maintains a top level node that all
        initial requests must be connected to. Example::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias. The following line is identical to the second line from the above example::

            sess.connect(s_get("HTTP"))

        Leverage callback methods to handle situations such as challenge response systems.
        A callback method must follow the message signature of :meth:`Session.example_test_case_callback`.
        Remember to include \\*\\*kwargs for forward-compatibility.

        Args:
            src (str or Request (pgrah.Node)): Source request name or request node
            dst (str or Request (pgrah.Node), optional): Destination request name or request node
            callback (def, optional): Callback function to pass received data to between node xmits. Default None.

        Returns:
            pgraph.Edge: The edge between the src and dst.
        """
        # if only a source was provided, then make it the destination and set the source to the root node.
        if dst is None:
            dst = src
            src = self.root

        # if source or destination is a name, resolve the actual node.
        if isinstance(src, six.string_types):
            src = self.find_node("name", src)

        if isinstance(dst, six.string_types):
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and self.find_node("name", src.name) is None:
            self.add_node(src)

        if self.find_node("name", dst.name) is None:
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = Connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge

    def export_file(self):
        """
        Dump various object values to disk.

        @see: import_file()
        """

        if not self.session_filename:
            return

        data = {
            "session_filename": self.session_filename,
            "index_start": self.total_mutant_index,
            "sleep_time": self.sleep_time,
            "restart_sleep_time": self.restart_sleep_time,
            "restart_interval": self.restart_interval,
            "web_port": self.web_port,
            "crash_threshold": self._crash_threshold_node,
            "total_num_mutations": self.total_num_mutations,
            "total_mutant_index": self.total_mutant_index,
            "monitor_results": self.monitor_results,
            "is_paused": self.is_paused,
        }

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(pickle.dumps(data, protocol=2)))
        fh.close()

    def feature_check(self):
        """Check all messages/features.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        for path in self._iterate_protocol():
            self._message_check(path)

    def fuzz(self):
        """Fuzz the entire protocol tree.

        Iterates through and fuzzes all fuzz cases, skipping according to
        self.skip and restarting based on self.restart_interval.

        If you want the web server to be available, your program must persist
        after calling this method. helpers.pause_for_signal() is
        available to this end.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        self._main_fuzz_loop((m for path in self._iterate_protocol() for m in self._iterate_single_node(path)))

    def fuzz_single_node_by_path(self, node_names):
        """Fuzz a particular node via the path in node_names.

        Args:
            node_names (list of str): List of node names leading to target.
        """
        node_edges = self._path_names_to_edges(node_names=node_names)

        self.total_mutant_index = 0
        self.total_num_mutations = self.nodes[node_edges[-1].dst].get_num_mutations()

        self._main_fuzz_loop(self._iterate_single_node(node_edges))

    def fuzz_by_name(self, name):
        """Fuzz a particular test case or node by name.

        Args:
            name (str): Name of node.
        """
        self.fuzz_single_node_by_path(re.split("->", name))

    def fuzz_single_case(self, mutant_index):
        """Fuzz a test case by mutant_index.

        Args:
            mutant_index (int): Positive non-zero integer.

        Returns:
            None

        Raises:
            sex.SulleyRuntimeError: If any error is encountered while executing the test case.
        """
        self.total_mutant_index = 0
        self.total_num_mutations = 1

        self._main_fuzz_loop(self._iterate_single_case_by_index(mutant_index))

    def _message_check(self, path):
        """Check messages for compatibility.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            path (list of Connection): Nodes (Requests) along the path to the target one.

        Returns:
            None
        """
        self.server_init()

        try:
            self._check_message(MutationContext(mutation=Mutation(message_path=path)))
        except KeyboardInterrupt:
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.BoofuzzRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.BoofuzzTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def _main_fuzz_loop(self, fuzz_case_iterator):
        """Execute main fuzz logic; takes an iterator of test cases.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through fuzz cases and yields MutationContext objects.
                 See _iterate_single_node() for details.

        Returns:
            None
        """
        if self.web_port is not None:
            self.server_init()

        try:
            self._start_target(self.targets[0])

            if self._reuse_target_connection:
                self.targets[0].open()
            num_cases_actually_fuzzed = 0
            for mutation_context in fuzz_case_iterator:
                if self.total_mutant_index < self._index_start:
                    continue
                elif self._index_end is not None and self.total_mutant_index > self._index_end:
                    break

                # Check restart interval
                if (
                    num_cases_actually_fuzzed
                    and self.restart_interval
                    and num_cases_actually_fuzzed % self.restart_interval == 0
                ):
                    self._fuzz_data_logger.open_test_step("restart interval of %d reached" % self.restart_interval)
                    self._restart_target(self.targets[0])

                self._fuzz_current_case(mutation_context)

                num_cases_actually_fuzzed += 1
            if self._reuse_target_connection:
                self.targets[0].close()

            if self._keep_web_open and self.web_port is not None:
                print(
                    "\nFuzzing session completed. Keeping webinterface up on localhost:{}".format(self.web_port),
                    "\nPress ENTER to close webinterface",
                )
                input()
        except KeyboardInterrupt:
            # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
            self.export_file()
            self._fuzz_data_logger.log_error("SIGINT received ... exiting")
            raise
        except exception.BoofuzzRestartFailedError:
            self._fuzz_data_logger.log_error("Restarting the target failed, exiting.")
            self.export_file()
            raise
        except exception.BoofuzzTargetConnectionFailedError:
            # exception should have already been handled but rethrown in order to escape test run
            pass
        except Exception:
            self._fuzz_data_logger.log_error("Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise
        finally:
            self._fuzz_data_logger.close_test()

    def _start_target(self, target):
        started = False
        for monitor in target.monitors:
            if monitor.start_target():
                started = True
                break
        if started:
            for monitor in target.monitors:
                monitor.post_start_target(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self)

    def import_file(self):
        """
        Load various object values from disk.

        @see: export_file()
        """
        if self.session_filename is None:
            return

        try:
            with open(self.session_filename, "rb") as f:
                data = pickle.loads(zlib.decompress(f.read()))
        except (IOError, zlib.error, pickle.UnpicklingError):
            return

        # update the skip variable to pick up fuzzing from last test case.
        self._index_start = data["total_mutant_index"]
        self.session_filename = data["session_filename"]
        self.sleep_time = data["sleep_time"]
        self.restart_sleep_time = data["restart_sleep_time"]
        self.restart_interval = data["restart_interval"]
        self.web_port = data["web_port"]
        self._crash_threshold_node = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index = data["total_mutant_index"]
        self.monitor_results = data["monitor_results"]
        self.is_paused = data["is_paused"]

    def num_mutations(self, this_node=None, path=()):
        """
        Number of total mutations in the graph. The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. The member variable self.total_num_mutations is updated appropriately by this routine.

        Args:
            this_node (request (node)): Current node that is being fuzzed. Default None.
            path (list): Nodes along the path to the current one being fuzzed. Default [].

        Returns:
            int: Total number of mutations in this session.
        """

        if this_node is None:
            this_node = self.root
            self.total_num_mutations = 0

        if isinstance(path, tuple):
            path = list(path)

        for edge in self.edges_from(this_node.id):
            next_node = self.nodes[edge.dst]
            self.total_num_mutations += next_node.get_num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self.num_mutations(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations

    def _pause_if_pause_flag_is_set(self):
        """
        If that pause flag is raised, enter an endless loop until it is lowered.
        """
        while 1:
            if self.is_paused:
                time.sleep(1)
            else:
                break

    def _check_for_passively_detected_failures(self, target, failure_already_detected=False):
        """Check for and log passively detected failures. Return True if any found.

        Args:
            target (Target): Target to be checked for failures.
            failure_already_detected (bool): If a failure was already detected.

        Returns:
            bool: True if failures were found. False otherwise.
        """
        has_crashed = False
        if len(target.monitors) > 0:
            self._fuzz_data_logger.open_test_step("Contact target monitors")
            # So, we need to run through the array two times. First, we check
            # if any of the monitors reported a failure and if so, we need to
            # gather a crash synopsis from them. We don't know whether
            # a monitor can provide a crash synopsis, but in any case, we'll
            # check. In the second run, we try to get crash synopsis from the
            # monitors that did not detect a crash as supplemental information.
            finished_monitors = []
            for monitor in target.monitors:
                if not monitor.post_send(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self):
                    has_crashed = True
                    self._fuzz_data_logger.log_fail(
                        "{0} detected crash on test case #{1}: {2}".format(
                            str(monitor), self.total_mutant_index, monitor.get_crash_synopsis()
                        )
                    )
                    finished_monitors.append(monitor)

            if not has_crashed and not failure_already_detected:
                self._fuzz_data_logger.log_pass("No crash detected.")
            else:
                for monitor in set(target.monitors) - set(finished_monitors):

                    synopsis = monitor.get_crash_synopsis()
                    if len(synopsis) > 0:
                        self._fuzz_data_logger.log_fail(
                            "{0} provided additional information for crash on #{1}: {2}".format(
                                str(monitor), self.total_mutant_index, monitor.get_crash_synopsis()
                            )
                        )
        return has_crashed

    def _get_monitor_data(self, target):
        """Query monitors for any data they may want to add to this test case.

        Args:
            target (Target): Monitor to query data from.
        """
        for monitor in target.monitors:
            data = monitor.retrieve_data()
            if data is not None and len(data) > 0:
                self._fuzz_data_logger.log_info(
                    "{0} captured {1} bytes of additional data for test case #{2}".format(
                        str(monitor), len(data), self.total_mutant_index
                    )
                )
                if self.total_mutant_index not in self.monitor_data:
                    self.monitor_data[self.total_mutant_index] = []

                self.monitor_data[self.total_mutant_index] += [data]

    def _process_failures(self, target):
        """Process any failures in self.crash_synopses.

        If self.crash_synopses contains any entries, perform these failure-related actions:
         - log failure summary if needed
         - save failures to self.monitor_results (for website)
         - exhaust node if crash threshold is reached
         - target restart

        Should be called after each fuzz test case.

        Args:
            target (Target): Target to restart if failure occurred.

        Returns:
            bool: True if any failures were found; False otherwise.
        """
        crash_synopses = self._fuzz_data_logger.failed_test_cases.get(self._fuzz_data_logger.all_test_cases[-1], [])
        if len(crash_synopses) > 0:
            self._fuzz_data_logger.open_test_step("Failure summary")

            # retrieve the primitive that caused the crash and increment it's individual crash count.
            self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant, 0) + 1
            self.crashing_primitives[self.fuzz_node] = self.crashing_primitives.get(self.fuzz_node, 0) + 1

            # print crash synopsis
            if len(crash_synopses) > 1:
                # Prepend a header if > 1 failure report, so that they are visible from the main web page
                synopsis = "({0} reports) {1}".format(len(crash_synopses), "\n".join(crash_synopses))
            else:
                synopsis = "\n".join(crash_synopses)
            self.monitor_results[self.total_mutant_index] = crash_synopses
            self._fuzz_data_logger.log_info(synopsis)

            if (
                self.fuzz_node.mutant is not None
                and self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node
            ):
                skipped = max(0, self.fuzz_node.get_num_mutations() - self.mutant_index)
                self._skip_current_node_after_current_test_case = True
                self._fuzz_data_logger.open_test_step(
                    "Crash threshold reached for this request, exhausting {0} mutants.".format(skipped)
                )
                self.total_mutant_index += skipped
                self.mutant_index += skipped
            elif (
                self.fuzz_node.mutant is not None
                and self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element
            ):
                if not isinstance(self.fuzz_node.mutant, primitives.Group) and not isinstance(
                    self.fuzz_node.mutant, blocks.Repeat
                ):
                    skipped = max(0, self.fuzz_node.mutant.get_num_mutations() - self.mutant_index)
                    self._skip_current_element_after_current_test_case = True
                    self._fuzz_data_logger.open_test_step(
                        "Crash threshold reached for this element, exhausting {0} mutants.".format(skipped)
                    )
                    self.total_mutant_index += skipped
                    self.mutant_index += skipped

            self._restart_target(target)
            return True
        else:
            return False

    def register_post_test_case_callback(self, method):
        """Register a post- test case method.

        The registered method will be called after each fuzz test case.

        Potential uses:
         * Closing down a connection.
         * Checking for expected responses.

        The order of callback events is as follows::

            pre_send() - req - callback ... req - callback - post-test-case-callback

        Args:
            method (function): A method with the same parameters as :func:`~Session.post_send`
        """
        self._callback_monitor.on_post_send.append(method)

    # noinspection PyUnusedLocal
    def example_test_case_callback(self, target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
        """
        Example call signature for methods given to :func:`~Session.connect` or
        :func:`~Session.register_post_test_case_callback`

        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.
            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.
            test_case_context (ProtocolSession): Context for test case-scoped data.
                :py:class:`ProtocolSession` :py:attr:`session_variables <ProtocolSession.session_variables>`
                values are generally set within a callback and referenced in elements via default values of type
                :py:class:`ProtocolSessionReference`.
            args: Implementations should include \\*args and \\**kwargs for forward-compatibility.
            kwargs: Implementations should include \\*args and \\**kwargs for forward-compatibility.
        """
        # default to doing nothing.
        self._fuzz_data_logger.log_info("No post_send callback registered.")

    # noinspection PyMethodMayBeStatic
    def _pre_send(self, target):
        """
        Execute custom methods to run prior to each fuzz request. The order of events is as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        Args:
            target (session.target): Target we are sending data to
        """

        for monitor in target.monitors:
            try:
                self._fuzz_data_logger.open_test_step("Monitor {}.pre_send()".format(str(monitor)))
                monitor.pre_send(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self)
            except Exception:
                self._fuzz_data_logger.log_error(
                    constants.ERR_CALLBACK_FUNC.format(func_name="{}.pre_send()".format(str(monitor)))
                    + traceback.format_exc()
                )

    def _restart_target(self, target):
        """
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. If custom restart methods are registered, execute them. Otherwise, do nothing.

        Args:
            target (session.target): Target we are restarting

        Raises:
             exception.BoofuzzRestartFailedError: if restart fails.
        """

        # TODO: reuse_target_connection seems to be only handled when using
        #       a custom callback. wtf?

        self._fuzz_data_logger.open_test_step("Restarting target")
        restarted = False
        if len(self.on_failure) > 0:
            for f in self.on_failure:
                self._fuzz_data_logger.open_test_step("Calling registered on_failure method")
                f(logger=self._fuzz_data_logger)
            restarted = True
        # vm restarting is the preferred method so try that before monitors.
        elif target.vmcontrol:
            self._fuzz_data_logger.log_info("Restarting target virtual machine")
            target.vmcontrol.restart_target()
            restarted = True
        # we always have at least one monitor; a Callback Monitor that handles all callbacks.
        else:
            for monitor in target.monitors:
                self._fuzz_data_logger.log_info("Restarting target process using {}".format(monitor.__class__.__name__))
                if monitor.restart_target(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self):
                    # TODO: doesn't this belong in the process monitor?
                    self._fuzz_data_logger.log_info("Giving the process 3 seconds to settle in")
                    time.sleep(3)
                    restarted = True
                    break

        if restarted:
            for monitor in target.monitors:
                monitor.post_start_target(target=self.targets[0], fuzz_data_logger=self._fuzz_data_logger, session=self)
        else:
            self._fuzz_data_logger.log_info(
                "No reset handler available... sleeping for {} seconds".format(self.restart_sleep_time)
            )
            time.sleep(self.restart_sleep_time)

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        target.monitors_alive()

    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc."""
        if not self.web_interface_thread.is_alive():
            # spawn the web interface.
            self.web_interface_thread.start()

    def _callback_current_node(self, node, edge, test_case_context):
        """Execute callback preceding current node.

        Args:
            test_case_context (ProtocolSession): Context for test case-scoped data.
            node (pgraph.node.node (Node), optional): Current Request/Node
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.

        Returns:
            bytes: Data rendered by current node if any; otherwise None.
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self._fuzz_data_logger.open_test_step("Callback function '{0}'".format(edge.callback.__name__))
            data = edge.callback(
                self.targets[0],
                self._fuzz_data_logger,
                session=self,
                node=node,
                edge=edge,
                test_case_context=test_case_context,
            )

        return data

    def transmit_normal(self, sock, node, edge, callback_data, mutation_context):
        """Render and transmit a non-fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
            mutation_context (MutationContext): active mutation context
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render(mutation_context=mutation_context)

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.BoofuzzTargetConnectionReset:
            # TODO: Switch _ignore_connection_reset for _ignore_transmission_error, or provide retry mechanism
            if self._ignore_connection_reset:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            # TODO: Switch _ignore_connection_aborted for _ignore_transmission_error, or provide retry mechanism
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_aborted:
                self._fuzz_data_logger.log_info(msg)
            else:
                raise BoofuzzFailure(msg)
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                raise BoofuzzFailure(message=str(e))

        try:  # recv
            if self._receive_data_after_each_request:
                self.last_recv = self.targets[0].recv()

                if self._check_data_received_each_request:
                    self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                    if not self.last_recv:
                        # Assume a crash?
                        raise BoofuzzFailure(message="Nothing received from target.")
                    else:
                        self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.BoofuzzTargetConnectionReset:
            if self._check_data_received_each_request:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                raise BoofuzzFailure(msg)
            else:
                self._fuzz_data_logger.log_info(msg)
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                raise BoofuzzFailure(str(e))

    def transmit_fuzz(self, sock, node, edge, callback_data, mutation_context):
        """Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
            mutation_context (MutationContext): Current mutation context.
        """
        if callback_data:
            data = callback_data
        else:
            data = self.fuzz_node.render(mutation_context)

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.BoofuzzTargetConnectionReset:
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(msg)
            else:
                raise BoofuzzFailure(msg)
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                raise BoofuzzFailure(str(e))

        received = b""
        try:  # recv
            if self._receive_data_after_fuzz:
                received = self.targets[0].recv()
        except exception.BoofuzzTargetConnectionReset:
            if self._check_data_received_each_request:
                raise BoofuzzFailure(message=constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno, socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                raise BoofuzzFailure(msg)
            else:
                self._fuzz_data_logger.log_info(msg)
            pass
        except exception.BoofuzzSSLError as e:
            if self._ignore_connection_ssl_errors:
                self._fuzz_data_logger.log_info(str(e))
            else:
                self._fuzz_data_logger.log_fail(str(e))
                raise BoofuzzFailure(str(e))
        self.last_recv = received

    def build_webapp_thread(self, port=constants.DEFAULT_WEB_UI_PORT):
        app.session = self
        http_server = HTTPServer(WSGIContainer(app))
        while True:
            try:
                http_server.listen(port)
            except socket.error as exc:
                # Only handle "Address already in use"
                if exc.errno != errno.EADDRINUSE:
                    raise
                port += 1
            else:
                self._fuzz_data_logger.log_info("Web interface can be found at http://localhost:%d" % port)
                break
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread

    def _iterate_protocol(self):
        """
        Iterates over fuzz cases and mutates appropriately.
        On each iteration, one may call fuzz_current_case to do the
        actual fuzzing.

        :raise sex.SullyRuntimeError:
        """
        # we can't fuzz if we don't have at least one target and one request.
        if not self.targets:
            raise exception.SullyRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id):
            raise exception.SullyRuntimeError("No requests specified in session")

        for x in self._iterate_protocol_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_protocol_recursive(self, this_node, path):
        """
        Recursively iterates over fuzz nodes. Used by _fuzz_case_iterator.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = self._message_path_to_str(path)
            logging.debug("fuzzing: {0}".format(message_path))
            self.fuzz_node = self.nodes[path[-1].dst]

            yield path

            # recursively fuzz the remainder of the nodes in the session graph.
            for x in self._iterate_protocol_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _iterate_single_node(self, path):
        """Iterate fuzz cases for the last node in path.

        Args:
            path (list of Connection): Nodes (Requests) along the path to the current one being fuzzed.

        Yields:
            Mutation: Mutation object describing this mutation.
        """
        self.fuzz_node = self.nodes[path[-1].dst]
        self.mutant_index = 0

        for mutation in self.fuzz_node.get_mutations(None):
            self.mutant_index += 1
            self.total_mutant_index += 1
            mutation.message_path = path
            yield MutationContext(mutation=mutation)

            if self._skip_current_node_after_current_test_case:
                self._skip_current_node_after_current_test_case = False
                break
            elif self._skip_current_element_after_current_test_case:
                self.fuzz_node.mutant.stop_mutations()
                self._skip_current_element_after_current_test_case = False
                continue
                # TODO reimplement node skip functionality

    def _iterate_single_case_by_index(self, test_case_index):
        fuzz_index = 1
        for path in self._iterate_protocol():
            for fuzz_args in self._iterate_single_node(path):
                if fuzz_index >= test_case_index:
                    self.total_mutant_index = 1
                    yield fuzz_args
                    break
                fuzz_index += 1

    def _path_names_to_edges(self, node_names):
        """Take a list of node names and return a list of edges describing that path.

        Args:
            node_names (list of str): List of node names describing a path.

        Returns:
            list of Connection: List of edges describing the path in node_names.
        """
        cur_node = self.root
        edge_path = []
        for node_name in node_names:
            next_node = None
            for edge in self.edges_from(cur_node.id):
                if self.nodes[edge.dst].name == node_name:
                    edge_path.append(edge)
                    next_node = self.nodes[edge.dst]
                    break
            if next_node is None:
                raise Exception("No edge found from {0} to {1}".format(cur_node.name, node_name))
            else:
                cur_node = next_node
        return edge_path

    def _check_message(self, mutation_context):
        """Sends the current message without fuzzing.

        Current test case is controlled by fuzz_case_iterator().

        Args:
            mutation_context (MutationContext): Current mutation context.
        """
        target = self.targets[0]
        mutation = mutation_context.mutation
        self.total_mutant_index += 1

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name_feature_check(mutation)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name,
            index=self.total_mutant_index,
            num_mutations=self.total_num_mutations,
            current_index=self.mutant_index,
            current_num_mutations=self.fuzz_node.get_num_mutations(),
        )

        try:
            self._open_connection_keep_trying(target)
            self._pre_send(target)

            for e in mutation.message_path[:-1]:
                prev_node = self.nodes[e.src]
                node = self.nodes[e.dst]
                protocol_session = ProtocolSession(
                    previous_message=prev_node,
                    current_message=node,
                )
                mutation_context.protocol_session = protocol_session
                self._fuzz_data_logger.open_test_step("Prep Node '{0}'".format(node.name))
                callback_data = self._callback_current_node(node=node, edge=e, test_case_context=protocol_session)
                self.transmit_normal(target, node, e, callback_data=callback_data, mutation_context=mutation_context)

            prev_node = self.nodes[mutation.message_path[-1].src]
            node = self.nodes[mutation.message_path[-1].dst]
            protocol_session = ProtocolSession(
                previous_message=prev_node,
                current_message=node,
            )
            mutation_context.protocol_session = protocol_session
            callback_data = self._callback_current_node(
                node=self.fuzz_node, edge=mutation.message_path[-1], test_case_context=protocol_session
            )

            self._fuzz_data_logger.open_test_step("Node Under Test '{0}'".format(self.fuzz_node.name))
            self.transmit_normal(
                target,
                self.fuzz_node,
                mutation.message_path[-1],
                callback_data=callback_data,
                mutation_context=mutation_context,
            )

            self._check_for_passively_detected_failures(target)
            if not self._reuse_target_connection:
                target.close()

            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
                time.sleep(self.sleep_time)
        finally:
            if self._process_failures(target=target):
                print("FAIL: {0}".format(test_case_name))
            else:
                print("PASS: {0}".format(test_case_name))

            self._get_monitor_data(target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()

    def _fuzz_current_case(self, mutation_context):
        """
        Fuzzes the current test case. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            mutation_context (MutationContext): Current mutation context.

        """
        target = self.targets[0]
        mutation = mutation_context.mutation

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name(mutation)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name,
            index=self.total_mutant_index,
            num_mutations=self.total_num_mutations,
            current_index=self.mutant_index,
            current_num_mutations=self.fuzz_node.get_num_mutations(),
        )

        self._fuzz_data_logger.log_info(
            "Type: %s. Default value: %s. Case %d of %d overall."
            % (
                type(self.fuzz_node.mutant).__name__,
                # TODO: Original value is not always attainable here, in the case of dynamic default values.
                # This output could be easily removed, and with some effort made dynamically available in the web view.
                # repr(self.fuzz_node.mutant.original_value(mutation_context=mutation_context)),
                b"",
                self.total_mutant_index,
                self.total_num_mutations,
            )
        )

        try:
            self._open_connection_keep_trying(target)

            self._pre_send(target)

            for e in mutation.message_path[:-1]:
                prev_node = self.nodes[e.src]
                node = self.nodes[e.dst]
                protocol_session = ProtocolSession(
                    previous_message=prev_node,
                    current_message=node,
                )
                mutation_context.protocol_session = protocol_session
                callback_data = self._callback_current_node(node=node, edge=e, test_case_context=protocol_session)
                self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                self.transmit_normal(target, node, e, callback_data=callback_data, mutation_context=mutation_context)

            prev_node = self.nodes[mutation.message_path[-1].src]
            node = self.nodes[mutation.message_path[-1].dst]
            protocol_session = ProtocolSession(
                previous_message=prev_node,
                current_message=node,
            )
            mutation_context.protocol_session = protocol_session
            callback_data = self._callback_current_node(
                node=self.fuzz_node, edge=mutation.message_path[-1], test_case_context=protocol_session
            )
            self._fuzz_data_logger.open_test_step("Fuzzing Node '{0}'".format(self.fuzz_node.name))
            self.transmit_fuzz(
                target,
                self.fuzz_node,
                mutation.message_path[-1],
                callback_data=callback_data,
                mutation_context=mutation_context,
            )

            self._check_for_passively_detected_failures(target=target)
            if not self._reuse_target_connection:
                target.close()

            if self.sleep_time > 0:
                self._fuzz_data_logger.open_test_step("Sleep between tests.")
                self._sleep(self.sleep_time)
        except BoofuzzFailure as e:
            self._fuzz_data_logger.log_fail(e.message)
            self._check_for_passively_detected_failures(target=target, failure_already_detected=True)
        finally:
            self._process_failures(target=target)
            self._fuzz_data_logger.close_test_case()
            self.export_file()

    def _open_connection_keep_trying(self, target):
        """Open connection and if it fails, keep retrying.

        Args:
            target (Target): Target to open.
        """
        if not self._reuse_target_connection:
            out_of_available_sockets_count = 0
            unable_to_connect_count = 0
            initial_time = time.time()

            while True:
                try:
                    target.open()
                    break  # break if no exception
                except exception.BoofuzzTargetConnectionFailedError:
                    if self.restart_threshold and unable_to_connect_count >= self.restart_threshold:
                        self._fuzz_data_logger.log_info(
                            "Unable to reconnect to target: Reached threshold of {0} retries. Ending fuzzing.".format(
                                self.restart_threshold
                            )
                        )
                        raise
                    elif self.restart_timeout and time.time() >= initial_time + self.restart_timeout:
                        self._fuzz_data_logger.log_info(
                            "Unable to reconnect to target: Reached restart timeout of {0}s. Ending fuzzing.".format(
                                self.restart_timeout
                            )
                        )
                        raise
                    else:
                        self._fuzz_data_logger.log_info(constants.WARN_CONN_FAILED_TERMINAL)
                        self._restart_target(target)
                        unable_to_connect_count += 1
                except exception.BoofuzzOutOfAvailableSockets:
                    out_of_available_sockets_count += 1
                    if out_of_available_sockets_count == 50:
                        raise exception.BoofuzzError("There are no available sockets. Ending fuzzing.")
                    self._fuzz_data_logger.log_info("There are no available sockets. Waiting for another 5 seconds.")
                    time.sleep(5)

    def _sleep(self, seconds):
        self._fuzz_data_logger.log_info("sleeping for %f seconds" % seconds)
        time.sleep(seconds)

    def _test_case_name_feature_check(self, mutation):
        message_path = self._message_path_to_str(mutation.message_path)
        return "FEATURE-CHECK->{0}".format(message_path)

    def _test_case_name(self, mutation):
        """Get long test case name.

        Args:
            mutation (Mutation): Mutation to get name from.

        Returns:
            Long formatted test case name
        """
        message_path = self._message_path_to_str(mutation.message_path)
        primitive_path = next(iter(mutation.mutations))
        return "{0}:{1}:{2}".format(message_path, primitive_path, self.mutant_index)

    def _message_path_to_str(self, message_path):
        return "->".join([self.nodes[e.dst].name for e in message_path])

    def test_case_data(self, index):
        """Return test case data object (for use by web server)

        Args:
            index (int): Test case index

        Returns:
            DataTestCase: Test case data object
        """
        return self._db_logger.get_test_case_data(index=index)
