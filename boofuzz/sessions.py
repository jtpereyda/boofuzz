from __future__ import absolute_import

import cPickle
import datetime
import itertools
import logging
import os
import re
import threading
import time
import traceback
import zlib

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer

from boofuzz import helpers
from . import blocks, constants
from . import event_hook
from . import fuzz_logger
from . import fuzz_logger_db
from . import fuzz_logger_text
from . import ifuzz_logger
from . import pgraph
from . import primitives
from . import exception
from .web.app import app

DEFAULT_MAX_RECV = 8192


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
    """

    def __init__(self, connection, procmon=None, procmon_options=None, netmon=None):
        self._fuzz_data_logger = None

        self._target_connection = connection
        self.procmon = procmon
        self.netmon = netmon

        # set these manually once target is instantiated.
        self.vmcontrol = None
        self.netmon_options = {}
        if procmon_options is None:
            procmon_options = {}
        self.procmon_options = procmon_options
        self.vmcontrol_options = {}

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._fuzz_data_logger.log_info('Closing target connection...')
        self._target_connection.close()
        self._fuzz_data_logger.log_info('Connection closed.')

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._fuzz_data_logger.log_info('Opening target connection ({0})...'.format(self._target_connection.info))
        self._target_connection.open()
        self._fuzz_data_logger.log_info('Connection opened.')

    def pedrpc_connect(self):
        """
        Pass specified target parameters to the PED-RPC server.
        """
        # If the process monitor is alive, set it's options
        if self.procmon:
            while 1:
                if self.procmon.alive():
                    break

                time.sleep(1)

            # connection established.
            for key, value in self.procmon_options.items():
                getattr(self.procmon, 'set_{0}'.format(key))(value)

        # If the network monitor is alive, set it's options
        if self.netmon:
            while 1:
                if self.netmon.alive():
                    break

                time.sleep(1)

            # connection established.
            for key in self.netmon_options.keys():
                eval('self.netmon.set_%s(self.netmon_options["%s"])' % (key, key))

    def recv(self, max_bytes=DEFAULT_MAX_RECV):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
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
        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_send(data)

        num_sent = self._target_connection.send(data=data)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_info("{0} bytes sent".format(num_sent))

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
    def procmon_results(self):
        return self._db_reader.failure_map

    @property
    def netmon_results(self):
        return {1: 'netmon results not saved in current database format'}

    @property
    def fuzz_node(self):
        return None

    @property
    def total_num_mutations(self):
        return 100  # TODO upgrade database format to store this info

    @property
    def total_mutant_index(self):
        return 100  # TODO SELECT COUNT(*) FROM cases -- But watch out for partially finished case

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
        return 'finished'


class WebApp(object):
    """Serve fuzz data over HTTP.

    Args:
        session_info (SessionInfo): Object providing information on session
        web_port (int):         Port for monitoring fuzzing campaign via a web browser. Default 26000.
    """

    def __init__(self, session_info, web_port=constants.DEFAULT_WEB_UI_PORT, web_addr='localhost'):
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
        """Called by fuzz() to initialize variables, web interface, etc.
        """
        if not self._web_interface_thread.isAlive():
            # spawn the web interface.
            self._web_interface_thread.start()


def open_test_run(db_filename, port=constants.DEFAULT_WEB_UI_PORT, address='localhost'):
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
        crash_threshold_request (int):  Maximum number of crashes allowed before a request is exhausted. Default 12.
        crash_threshold_element (int):  Maximum number of crashes allowed before an element is exhausted. Default 3.
        restart_sleep_time (int): Time in seconds to sleep when target can't be restarted. Default 5.
        web_port (int):         Port for monitoring fuzzing campaign via a web browser. Default 26000.
        fuzz_data_logger (fuzz_logger.FuzzLogger): DEPRECATED. Use fuzz_loggers instead.
        fuzz_loggers (list of ifuzz_logger.IFuzzLogger): For saving test data and results.. Default Log to STDOUT.
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
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.

        log_level (int):        DEPRECATED Unused. Logger settings are now configured in fuzz_data_logger.
                                Was once used to set the log level.
        logfile (str):          DEPRECATED Unused. Logger settings are now configured in fuzz_data_logger.
                                Was once the name of the log file.
        logfile_level (int):    DEPRECATED Unused. Logger settings are now configured in fuzz_data_logger.
                                Was once used to set the log level for the logfile. Default logger.INFO.
    """

    def __init__(self, session_filename=None, index_start=1, index_end=None, sleep_time=0.0,
                 restart_interval=0,
                 web_port=constants.DEFAULT_WEB_UI_PORT,
                 crash_threshold_request=12,
                 crash_threshold_element=3,
                 restart_sleep_time=5,
                 fuzz_data_logger=None,
                 fuzz_loggers=None,
                 receive_data_after_each_request=True,
                 check_data_received_each_request=False,
                 receive_data_after_fuzz=False,
                 log_level=logging.INFO, logfile=None, logfile_level=logging.DEBUG,
                 ignore_connection_reset=False,
                 ignore_connection_aborted=False,
                 ignore_connection_issues_when_sending_fuzz_data=True,
                 target=None,
                 ):
        self._ignore_connection_reset = ignore_connection_reset
        self._ignore_connection_aborted = ignore_connection_aborted
        self._ignore_connection_issues_when_sending_fuzz_data = ignore_connection_issues_when_sending_fuzz_data
        _ = log_level
        _ = logfile
        _ = logfile_level

        super(Session, self).__init__()

        self.session_filename = session_filename
        self._index_start = max(index_start, 1)
        self._index_end = index_end
        self.sleep_time = sleep_time
        self.restart_interval = restart_interval
        self.web_port = web_port
        self._crash_threshold_node = crash_threshold_request
        self._crash_threshold_element = crash_threshold_element
        self.restart_sleep_time = restart_sleep_time
        if fuzz_data_logger is not None:
            raise exception.BoofuzzError('Session fuzz_data_logger is deprecated. Use fuzz_loggers instead!')
        if fuzz_loggers is None:
            fuzz_loggers = [fuzz_logger_text.FuzzLoggerText()]

        helpers.mkdir_safe(os.path.join(constants.RESULTS_DIR))
        self._run_id = datetime.datetime.utcnow().replace(microsecond=0).isoformat().replace(':', '-')
        self._db_filename = os.path.join(constants.RESULTS_DIR, 'run-{0}.db'.format(self._run_id))
        self._db_logger = fuzz_logger_db.FuzzLoggerDb(self._db_filename)

        self._fuzz_data_logger = fuzz_logger.FuzzLogger(fuzz_loggers=[self._db_logger] + fuzz_loggers)
        self._check_data_received_each_request = check_data_received_each_request
        self._receive_data_after_each_request = receive_data_after_each_request
        self._receive_data_after_fuzz = receive_data_after_fuzz
        self._skip_current_node_after_current_test_case = False
        self._skip_current_element_after_current_test_case = False
        self._post_test_case_methods = []

        self.web_interface_thread = self.build_webapp_thread(port=self.web_port)

        self.total_num_mutations = 0
        self.total_mutant_index = 0
        self.fuzz_node = None
        self.targets = []
        self.netmon_results = {}
        self.procmon_results = {}  # map of test case indices to list of crash synopsis strings (failed cases only)
        self.is_paused = False
        self.crashing_primitives = {}
        self.on_failure = event_hook.EventHook()

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root = pgraph.Node()
        self.root.name = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv = None
        self.last_send = None

        self.add_node(self.root)

        if target is not None:
            try:
                self.add_target(target=target)
            except exception.BoofuzzRpcError as e:
                self._fuzz_data_logger.log_error(str(e))
                raise

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
        target.pedrpc_connect()
        target.set_fuzz_data_logger(fuzz_data_logger=self._fuzz_data_logger)

        # add target to internal list.
        self.targets.append(target)

    def connect(self, src, dst=None, callback=None):
        """
        Create a connection between the two requests (nodes) and register an optional callback to process in between
        transmissions of the source and destination request. Leverage this functionality to handle situations such as
        challenge response systems. The session class maintains a top level node that all initial requests must be
        connected to. Example::

            sess = sessions.session()
            sess.connect(sess.root, s_get("HTTP"))

        If given only a single parameter, sess.connect() will default to attaching the supplied node to the root node.
        This is a convenient alias and is identical to the second line from the above example::

            sess.connect(s_get("HTTP"))

        If you register callback method, it must follow this prototype::

            def callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as session.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet. As another
        example, if you need to fill in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

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
        if type(src) is str:
            src = self.find_node("name", src)

        if type(dst) is str:
            dst = self.find_node("name", dst)

        # if source or destination is not in the graph, add it.
        if src != self.root and not self.find_node("name", src.name):
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
            "netmon_results": self.netmon_results,
            "procmon_results": self.procmon_results,
            "is_paused": self.is_paused
        }

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(cPickle.dumps(data, protocol=2)))
        fh.close()

    def feature_check(self):
        """Check all messages/features.

        Returns:
            None
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        self._message_check(self._iterate_messages())

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

        self._main_fuzz_loop(self._iterate_protocol())

    def fuzz_single_node_by_path(self, node_names):
        """Fuzz a particular node via the path in node_names.

        Args:
            node_names (list of str): List of node names leading to target.
        """
        node_edges = self._path_names_to_edges(node_names=node_names)

        self.total_mutant_index = 0
        self.total_num_mutations = self.nodes[node_edges[-1].dst].num_mutations()

        self._main_fuzz_loop(self._iterate_single_node(node_edges))

    def fuzz_by_name(self, name):
        """Fuzz a particular test case or node by name.

        Args:
            name (str): Name of node.
        """
        self.fuzz_single_node_by_path(re.split('->', name))

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

    def _message_check(self, fuzz_case_iterator):
        """Check messages for compatibility.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through

        Returns:
            None
        """
        self.server_init()

        try:
            for fuzz_args in fuzz_case_iterator:
                self._check_message(*fuzz_args)
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
            self._fuzz_data_logger.log_error(
                "Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def _main_fuzz_loop(self, fuzz_case_iterator):
        """Execute main fuzz logic; takes an iterator of test cases.

        Preconditions: `self.total_mutant_index` and `self.total_num_mutations` are set properly.

        Args:
            fuzz_case_iterator (Iterable): An iterator that walks through fuzz cases.

        Returns:
            None
        """
        self.server_init()

        try:
            num_cases_actually_fuzzed = 0
            for fuzz_args in fuzz_case_iterator:
                if self.total_mutant_index < self._index_start:
                    continue
                elif self._index_end is not None and self.total_mutant_index > self._index_end:
                    break

                # Check restart interval
                if num_cases_actually_fuzzed \
                        and self.restart_interval \
                        and num_cases_actually_fuzzed % self.restart_interval == 0:
                    self._fuzz_data_logger.open_test_step("restart interval of %d reached" % self.restart_interval)
                    self.restart_target(self.targets[0])

                self._fuzz_current_case(*fuzz_args)

                num_cases_actually_fuzzed += 1
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
            self._fuzz_data_logger.log_error(
                "Unexpected exception! {0}".format(traceback.format_exc()))
            self.export_file()
            raise

    def import_file(self):
        """
        Load various object values from disk.

        @see: export_file()
        """
        if self.session_filename is None:
            return

        try:
            with open(self.session_filename, "rb") as f:
                data = cPickle.loads(zlib.decompress(f.read()))
        except (IOError, zlib.error, cPickle.UnpicklingError):
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
        self.netmon_results = data["netmon_results"]
        self.procmon_results = data["procmon_results"]
        self.is_paused = data["is_paused"]

    # noinspection PyMethodMayBeStatic
    def log(self, msg, level=1):
        raise Exception("Depreciated!")

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
            self.total_num_mutations += next_node.num_mutations()

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

    def _stop_netmon(self, target):
        if target.netmon:
            captured_bytes = target.netmon.post_send()
            self._fuzz_data_logger.log_info(
                "netmon captured %d bytes for test case #%d" % (captured_bytes, self.total_mutant_index))
            self.netmon_results[self.total_mutant_index] = captured_bytes

    def _check_procmon_failures(self, target):
        """Check for and log any failures from the procmon. Return True if any found.

        Returns:
            bool: True if failures were found. False otherwise.
        """
        if target.procmon:
            self._fuzz_data_logger.open_test_step("Contact process monitor")
            self._fuzz_data_logger.log_check("procmon.post_send()")
            if target.procmon.post_send():
                self._fuzz_data_logger.log_pass("No crash detected.")
            else:
                self._fuzz_data_logger.log_fail(
                    "procmon detected crash on test case #{0}: {1}".format(self.total_mutant_index,
                                                                           target.procmon.get_crash_synopsis()))
                return True
        return False

    def _check_for_passively_detected_failures(self, target):
        """Check for and log passively detected failures. Return True if any found.

        Returns:
            bool: True if falures were found. False otherwise.
        """
        return self._check_procmon_failures(target=target)

    def _process_failures(self, target):
        """Process any failures in self.crash_synopses.

        If self.crash_synopses contains any entries, perform these failure-related actions:
         - log failure summary if needed
         - save failures to self.procmon_results (for website)
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
            self.procmon_results[self.total_mutant_index] = crash_synopses
            self._fuzz_data_logger.log_info(synopsis)

            if self.fuzz_node.mutant is not None and \
                    self.crashing_primitives[self.fuzz_node] >= self._crash_threshold_node:
                skipped = self.fuzz_node.num_mutations() - self.fuzz_node.mutant_index
                self._skip_current_node_after_current_test_case = True
                self._fuzz_data_logger.open_test_step(
                    "Crash threshold reached for this request, exhausting {0} mutants.".format(skipped))
                self.total_mutant_index += skipped
                self.fuzz_node.mutant_index += skipped
            elif self.fuzz_node.mutant is not None and \
                    self.crashing_primitives[self.fuzz_node.mutant] >= self._crash_threshold_element:
                if not isinstance(self.fuzz_node.mutant, primitives.Group) \
                        and not isinstance(self.fuzz_node.mutant, blocks.Repeat):
                    skipped = self.fuzz_node.mutant.num_mutations() - self.fuzz_node.mutant.mutant_index
                    self._skip_current_element_after_current_test_case = True
                    self._fuzz_data_logger.open_test_step(
                        "Crash threshold reached for this element, exhausting {0} mutants.".format(skipped))
                    self.total_mutant_index += skipped
                    self.fuzz_node.mutant_index += skipped

            self.restart_target(target)
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
        self._post_test_case_methods.append(method)

    # noinspection PyUnusedLocal
    def example_test_case_callback(self, target, fuzz_data_logger, session, *args, **kwargs):
        """
        Example call signature for methods given to :func:`~Session.register_post_test_case_callback`.

        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.

            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.

            sock: DEPRECATED Included for backward-compatibility. Same as target.
            args: Implementations should include \*args and \**kwargs for forward-compatibility.
            kwargs: Implementations should include \*args and \**kwargs for forward-compatibility.
        """
        # default to doing nothing.
        self._fuzz_data_logger.log_info("No post_send callback registered.")

    # noinspection PyMethodMayBeStatic
    def pre_send(self, sock):
        """
        Overload or replace this routine to specify actions to run prior to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        Args:
            sock (Socket): Connected socket to target
        """

        # default to doing nothing.
        pass

    def restart_target(self, target):
        """
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. Otherwise, do nothing.

        Args:
            target (session.target): Target we are restarting

        @raise sex.BoofuzzRestartFailedError if restart fails.
        """

        self._fuzz_data_logger.open_test_step("restarting target")
        if len(self.on_failure) > 0:
            for f in self.on_failure:
                self._fuzz_data_logger.open_test_step("calling registered on_failure method")
                f(logger=self._fuzz_data_logger)
        # vm restarting is the preferred method so try that before procmon.
        elif target.vmcontrol:
            self._fuzz_data_logger.log_info("restarting target virtual machine")
            target.vmcontrol.restart_target()

        # if we have a connected process monitor, restart the target process.
        elif target.procmon:
            self._fuzz_data_logger.log_info("restarting target process")

            if not target.procmon.restart_target():
                raise exception.BoofuzzRestartFailedError()

            self._fuzz_data_logger.log_info("giving the process 3 seconds to settle in ")
            time.sleep(3)

        # otherwise all we can do is wait a while for the target to recover on its own.
        else:
            self._fuzz_data_logger.log_info(
                "no reset handler available... sleeping for %d seconds" % self.restart_sleep_time
            )
            time.sleep(self.restart_sleep_time)

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        target.pedrpc_connect()

    def server_init(self):
        """Called by fuzz() to initialize variables, web interface, etc.
        """
        if not self.web_interface_thread.isAlive():
            # spawn the web interface.
            self.web_interface_thread.start()

    def _callback_current_node(self, node, edge):
        """Execute callback preceding current node.

        Returns:
            bytes: Data rendered by current node if any; otherwise None.
        """
        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            self._fuzz_data_logger.open_test_step('Callback function')
            data = edge.callback(self.targets[0], self._fuzz_data_logger, session=self, node=node, edge=edge)

        return data

    def transmit_normal(self, sock, node, edge, callback_data):
        """Render and transmit a non-fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render()

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.BoofuzzTargetConnectionReset:
            # TODO: Switch _ignore_connection_reset for _ignore_transmission_error, or provide retry mechanism
            if self._ignore_connection_reset:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            # TODO: Switch _ignore_connection_aborted for _ignore_transmission_error, or provide retry mechanism
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_aborted:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)
        try:  # recv
            if self._receive_data_after_each_request:
                self.last_recv = self.targets[0].recv(10000)  # TODO: Remove magic number (10000)

                if self._check_data_received_each_request:
                    self._fuzz_data_logger.log_check("Verify some data was received from the target.")
                    if not self.last_recv:
                        # Assume a crash?
                        self._fuzz_data_logger.log_fail("Nothing received from target.")
                    else:
                        self._fuzz_data_logger.log_pass("Some data received from target.")
        except exception.BoofuzzTargetConnectionReset:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
            else:
                self._fuzz_data_logger.log_info(msg)

    def transmit_fuzz(self, sock, node, edge, callback_data):
        """Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            sock (Target, optional): Socket-like object on which to transmit node
            node (pgraph.node.node (Node), optional): Request/Node to transmit
            edge (pgraph.edge.edge (pgraph.edge), optional): Edge along the current fuzz path from "node" to next node.
            callback_data (bytes): Data from previous callback.
        """
        if callback_data:
            data = callback_data
        else:
            data = node.render()

        try:  # send
            self.targets[0].send(data)
            self.last_send = data
        except exception.BoofuzzTargetConnectionReset:
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._ignore_connection_issues_when_sending_fuzz_data:
                self._fuzz_data_logger.log_info(msg)
            else:
                self._fuzz_data_logger.log_fail(msg)

        try:  # recv
            if self._receive_data_after_fuzz:
                self.last_recv = self.targets[0].recv(10000)  # TODO: Remove magic number (10000)
        except exception.BoofuzzTargetConnectionReset:
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET)
            else:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_RESET)
        except exception.BoofuzzTargetConnectionAborted as e:
            msg = constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                    socket_errmsg=e.socket_errmsg)
            if self._check_data_received_each_request:
                self._fuzz_data_logger.log_fail(msg)
            else:
                self._fuzz_data_logger.log_info(msg)
            pass

    def build_webapp_thread(self, port=constants.DEFAULT_WEB_UI_PORT):
        app.session = self
        http_server = HTTPServer(WSGIContainer(app))
        http_server.listen(port)
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread

    def _iterate_messages(self):
        """Iterates over each message without mutations.

        :raise sex.SullyRuntimeError:
        """
        if not self.targets:
            raise exception.SullyRuntimeError("No targets specified in session")

        if not self.edges_from(self.root.id):
            raise exception.SullyRuntimeError("No requests specified in session")

        self._reset_fuzz_state()

        for x in self._iterate_messages_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_messages_recursive(self, this_node, path):
        """Recursively iterates over messages. Used by _iterate_messages.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        :raise sex.SullyRuntimeError:
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we walk through it
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = "->".join([self.nodes[e.dst].name for e in path])
            logging.debug('checking: {0}'.format(message_path))

            self.fuzz_node = self.nodes[path[-1].dst]
            self.total_mutant_index += 1
            yield (path,)

            for x in self._iterate_messages_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

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

        self._reset_fuzz_state()

        for x in self._iterate_protocol_recursive(this_node=self.root, path=[]):
            yield x

    def _iterate_protocol_recursive(self, this_node, path):
        """
        Recursively iterates over fuzz nodes. Used by _fuzz_case_iterator.

        Args:
            this_node (node.Node): Current node that is being fuzzed.
            path (list of Connection): List of edges along the path to the current one being fuzzed.

        :raise sex.SullyRuntimeError:
        """
        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            message_path = "->".join([self.nodes[e.dst].name for e in path])
            logging.debug('fuzzing: {0}'.format(message_path))

            for x in self._iterate_single_node(path):
                yield x

            # recursively fuzz the remainder of the nodes in the session graph.
            for x in self._iterate_protocol_recursive(self.fuzz_node, path):
                yield x

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def _iterate_single_node(self, path):
        """Iterate fuzz cases for the last node in path.

        Args:
            path (list of Connection): Nodes along the path to the current one being fuzzed.

        Raises:
            sex.SullyRuntimeError:
        """
        self.fuzz_node = self.nodes[path[-1].dst]
        # Loop through and yield all possible mutations of the fuzz node.
        # Note: when mutate() returns False, the node has been reverted to the default (valid) state.
        while self.fuzz_node.mutate():
            self.total_mutant_index += 1
            yield (path,)

            if self._skip_current_node_after_current_test_case:
                self._skip_current_node_after_current_test_case = False
                break
            elif self._skip_current_element_after_current_test_case:
                self._skip_current_element_after_current_test_case = False
                self.fuzz_node.skip_element()
        self.fuzz_node.reset()

    def _iterate_single_case_by_index(self, test_case_index):
        fuzz_index = 1
        for fuzz_args in self._iterate_protocol():
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

    def _check_message(self, path):
        """Sends the current message without fuzzing.

        Current test case is controlled by fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name_feature_check(path)

        self._fuzz_data_logger.open_test_case(
            "{0}: {1}".format(self.total_mutant_index, test_case_name),
            name=test_case_name, index=self.total_mutant_index)

        try:
            if target.procmon:
                self._fuzz_data_logger.open_test_step('Calling procmon pre_send()')
                target.procmon.pre_send(self.total_mutant_index)

            if target.netmon:
                self._fuzz_data_logger.open_test_step('Calling netmon pre_send()')
                target.netmon.pre_send(self.total_mutant_index)

            try:
                target.open()
            except exception.BoofuzzTargetConnectionFailedError:
                self._fuzz_data_logger.log_error(constants.ERR_CONN_FAILED_TERMINAL)
                raise

            self.pre_send(target)

            for e in path[:-1]:
                node = self.nodes[e.dst]
                self._fuzz_data_logger.open_test_step("Prep Node '{0}'".format(node.name))
                callback_data = self._callback_current_node(node=node, edge=e)
                self.transmit_normal(target, node, e, callback_data=callback_data)

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1])

            self._fuzz_data_logger.open_test_step("Node Under Test '{0}'".format(self.fuzz_node.name))
            self.transmit_normal(target, self.fuzz_node, path[-1], callback_data=callback_data)
            target.close()

            self._post_send(target)
            self._check_procmon_failures(target)

            self._fuzz_data_logger.open_test_step("Sleep between tests.")
            self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
            time.sleep(self.sleep_time)
        finally:
            if self._process_failures(target=target):
                print("FAIL: {0}".format(test_case_name))
            else:
                print("PASS: {0}".format(test_case_name))
            self._stop_netmon(target)
            self.export_file()

    def _fuzz_current_case(self, path):
        """
        Fuzzes the current test case. Current test case is controlled by
        fuzz_case_iterator().

        Args:
            path(list of Connection): Path to take to get to the target node.

        """
        target = self.targets[0]

        self._pause_if_pause_flag_is_set()

        test_case_name = self._test_case_name(path, self.fuzz_node.mutant)

        self._fuzz_data_logger.open_test_case("{0}: {1}".format(self.total_mutant_index, test_case_name),
                                              name=test_case_name, index=self.total_mutant_index)

        self._fuzz_data_logger.log_info(
            "Type: %s. Default value: %s. Case %d of %d overall." % (
                type(self.fuzz_node.mutant).__name__,
                repr(self.fuzz_node.mutant.original_value),
                self.total_mutant_index,
                self.total_num_mutations))

        if target.procmon:
            self._fuzz_data_logger.open_test_step('Calling procmon pre_send()')
            target.procmon.pre_send(self.total_mutant_index)

        if target.netmon:
            self._fuzz_data_logger.open_test_step('Calling netmon pre_send()')
            target.netmon.pre_send(self.total_mutant_index)

        try:
            try:
                target.open()
            except exception.BoofuzzTargetConnectionFailedError:
                self._fuzz_data_logger.log_error(constants.ERR_CONN_FAILED_TERMINAL)
                raise

            self.pre_send(target)

            for e in path[:-1]:
                node = self.nodes[e.dst]
                callback_data = self._callback_current_node(node=node, edge=e)
                self._fuzz_data_logger.open_test_step("Transmit Prep Node '{0}'".format(node.name))
                self.transmit_normal(target, node, e, callback_data=callback_data)

            callback_data = self._callback_current_node(node=self.fuzz_node, edge=path[-1])
            self._fuzz_data_logger.open_test_step("Fuzzing Node '{0}'".format(self.fuzz_node.name))
            self.transmit_fuzz(target, self.fuzz_node, path[-1], callback_data=callback_data)
            target.close()

            if not self._check_for_passively_detected_failures(target=target):
                self._post_send(target)
                self._check_procmon_failures(target=target)

            self._fuzz_data_logger.open_test_step("Sleep between tests.")
            self._fuzz_data_logger.log_info("sleeping for %f seconds" % self.sleep_time)
            time.sleep(self.sleep_time)
        finally:
            self._process_failures(target=target)
            self._stop_netmon(target=target)
            self.export_file()

    def _test_case_name_feature_check(self, path):
        message_path = "->".join([self.nodes[e.dst].name for e in path])
        return "FEATURE-CHECK->{0}".format(message_path)

    def _test_case_name(self, path, mutated_element):
        message_path = "->".join([self.nodes[e.dst].name for e in path])
        if mutated_element.name:
            primitive_under_test = mutated_element.name
        else:
            primitive_under_test = 'no-name'
        return "{0}.{1}.{2}".format(message_path, primitive_under_test, self.fuzz_node.mutant_index)

    def _post_send(self, target):
        try:
            deprecated_callbacks = [self.post_send]
        except AttributeError:
            deprecated_callbacks = []
        if len(self._post_test_case_methods) + len(deprecated_callbacks) > 0:
            try:
                for f in itertools.chain(self._post_test_case_methods, deprecated_callbacks):
                    self._fuzz_data_logger.open_test_step('Post- test case callback: "{0}"'.format(f.__name__))
                    f(target=target, fuzz_data_logger=self._fuzz_data_logger, session=self, sock=target)
            except exception.BoofuzzTargetConnectionReset:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_RESET_FAIL)
            except exception.BoofuzzTargetConnectionAborted as e:
                self._fuzz_data_logger.log_info(constants.ERR_CONN_ABORTED.format(socket_errno=e.socket_errno,
                                                                                  socket_errmsg=e.socket_errmsg))
                pass
            except exception.BoofuzzTargetConnectionFailedError:
                self._fuzz_data_logger.log_fail(constants.ERR_CONN_FAILED)
            except Exception:
                self._fuzz_data_logger.log_fail(
                    "Custom post_send method raised uncaught Exception." + traceback.format_exc())
            finally:
                self._fuzz_data_logger.open_test_step('Cleaning up connections from callbacks')
                target.close()

    def _reset_fuzz_state(self):
        """
        Restart the object's fuzz state.

        :return: None
        """
        self.total_mutant_index = 0
        if self.fuzz_node:
            self.fuzz_node.reset()

    def test_case_data(self, index):
        """Return test case data object (for use by web server)

        Args:
            index (int): Test case index

        Returns:
            DataTestCase: Test case data object
        """
        return self._db_logger.get_test_case_data(index=index)
