import sys
import zlib
import time
import socket
import signal
import cPickle
import threading
import logging
import blocks
import pgraph
import sex
import primitives
import socket_connection
import ifuzz_logger

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from web.app import app

from sulley import helpers


class Target(object):
    """
    Target descriptor container.
    Encapsulates (socket) connection logic for the target, as well as pedrpc connection logic.

    Contains a logger which is configured by Session.add_target().

    Examples:
        tcp_target = Target(host='127.0.0.1', port=17971)
        udp_target = Target(host='127.0.0.1', port=17971, proto='udp')
        raw_target = Target(host='eth0')
        eth_target = Target(host='eth0', l2_dst='\xFF'*6)
    """

    def __init__(self,
                 host,
                 port=None,
                 proto="tcp",
                 bind=None,
                 timeout=5.0,
                 ethernet_proto=socket_connection.ETH_P_IP,
                 l2_dst='\xFF' * 6):
        """
        @type  host:    str
        @param host:    Hostname or IP address of target system,
                        or network interface string if using raw-l2 or raw-l3.

        @type  port:    int
        @param port:    Port of target service. Required for proto values 'tcp', 'udp', 'ssl'.

        @type  proto:   str
        @kwarg proto:   (Optional, def="tcp") Communication protocol ("tcp", "udp", "ssl", "raw-l2", "raw-l3")
                        raw-l2: Send packets at layer 2. Must include link layer header (e.g. Ethernet frame).
                        raw-l3: Send packets at layer 3. Must include network protocol header (e.g. IPv4).

        @type  bind:    tuple (host, port)
        @kwarg bind:    (Optional, def=None) Socket bind address and port. Required if using recv() with 'udp' protocol.

        @type  timeout: float
        @kwarg timeout: (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out

        @type ethernet_proto:
                        int
        @kwarg ethernet_proto:
                        (Optional, def=ETH_P_IP (0x0800)) Ethernet protocol when using 'raw-l3'. 16 bit integer.
                        See "if_ether.h" in Linux documentation for more options.

        @type l2_dst:   str
        @kwarg l2_dst:  (Optional, def='\xFF\xFF\xFF\xFF\xFF\xFF' (broadcast))
                        Layer 2 destination address (e.g. MAC address). Used only by 'raw-l3'.
        """
        self._logger = None
        self._fuzz_data_logger = None

        self._target_connection = socket_connection.SocketConnection(
            host=host, port=port, proto=proto, bind=bind, timeout=timeout,
            ethernet_proto=ethernet_proto, l2_dst=l2_dst)

        # set these manually once target is instantiated.
        self.netmon = None
        self.procmon = None
        self.vmcontrol = None
        self.netmon_options = {}
        self.procmon_options = {}
        self.vmcontrol_options = {}

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self._target_connection.close()

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self._target_connection.open()

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
            for key in self.procmon_options.keys():
                eval('self.procmon.set_%s(self.procmon_options["%s"])' % (key, key))

        # If the network monitor is alive, set it's options
        if self.netmon:
            while 1:
                if self.netmon.alive():
                    break

                time.sleep(1)

            # connection established.
            for key in self.netmon_options.keys():
                eval('self.netmon.set_%s(self.netmon_options["%s"])' % (key, key))

    def recv(self, max_bytes):
        """
        Receive up to max_bytes data from the target.

        :param max_bytes: Maximum number of bytes to receive.
        :type max_bytes: int

        :return: Received data.
        """
        data = self._target_connection.recv(max_bytes=max_bytes)

        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_recv(data)

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        :param data: Data to send.

        :return: None
        """
        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.log_send(data)
        self._target_connection.send(data=data)

    def set_logger(self, logger):
        """
        Set this object's (and it's aggregated classes') logger.

        :param logger: Logger to use.
        :type logger: logging.Logger

        :return: None
        """
        self._logger = logger
        self._target_connection.set_logger(logger=logger)

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

            def callback(session, node, edge, sock)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as sesson.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet.

        @type  src:      int
        @param src:      Edge source ID
        @type  dst:      int
        @param dst:      Edge destination ID
        @type  callback: def
        @param callback: (Optional, def=None) Callback function to pass received data to between node xmits
        """

        super(Connection, self).__init__(src, dst)

        self.callback = callback


class Session(pgraph.Graph):
    def __init__(self, session_filename=None, skip=0, sleep_time=1.0, log_level=logging.INFO, logfile=None,
                 logfile_level=logging.DEBUG, restart_interval=0, web_port=26000, crash_threshold=3,
                 restart_sleep_time=300, fuzz_data_logger=None):
        """
        Extends pgraph.graph and provides a container for architecting protocol dialogs.

        @type  session_filename:   str
        @kwarg session_filename:   (Optional, def=None) Filename to serialize persistent data to
        @type  skip:               int
        @kwarg skip:               (Optional, def=0) Number of test cases to skip
        @type  sleep_time:         float
        @kwarg sleep_time:         (Optional, def=1.0) Time to sleep in between tests
        @type  log_level:          int
        @kwarg log_level:          (Optional, def=logger.INFO) Set the log level
        @type  logfile:            str
        @kwarg logfile:            (Optional, def=None) Name of log file
        @type  logfile_level:      int
        @kwarg logfile_level:      (Optional, def=logger.INFO) Set the log level for the logfile
        @type  restart_interval:   int
        @kwarg restart_interval    (Optional, def=0) Restart the target after n test cases, disable by setting to 0
        @type  crash_threshold:    int
        @kwarg crash_threshold     (Optional, def=3) Maximum number of crashes allowed before a node is exhaust
        @type  restart_sleep_time: int
        @kwarg restart_sleep_time: (Optional, def=300) Time in seconds to sleep when target can't be restarted
        @type  web_port:	       int
        @kwarg web_port:           (Optional, def=26000) Port for monitoring fuzzing campaign via a web browser
        @type fuzz_data_logger:    ifuzz_logger.IFuzzLogger
        @kwarg fuzz_data_logger:   (Optional, def=None) For saving data sent to and from the target.
        """

        super(Session, self).__init__()

        self.session_filename = session_filename
        self.skip = skip
        self.sleep_time = sleep_time
        self.restart_interval = restart_interval
        self.web_port = web_port
        self.crash_threshold = crash_threshold
        self.restart_sleep_time = restart_sleep_time
        self._fuzz_data_logger = fuzz_data_logger

        self.web_interface_thread = self.build_webapp_thread(port=self.web_port)

        # Initialize logger
        self.logger = logging.getLogger("Sulley_logger")
        self.logger.setLevel(log_level)
        self.logger.propagate = False  # Propagating messages to the root logger can result in duplicate logs.
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] -> %(message)s')

        if logfile:
            filehandler = logging.FileHandler(logfile)
            filehandler.setLevel(logfile_level)
            filehandler.setFormatter(formatter)
            self.logger.addHandler(filehandler)

        consolehandler = logging.StreamHandler()
        consolehandler.setFormatter(formatter)
        consolehandler.setLevel(log_level)

        self.logger.addHandler(consolehandler)

        self.total_num_mutations = 0
        self.total_mutant_index = 0
        self.fuzz_node = None
        self.targets = []
        self.netmon_results = {}
        self.procmon_results = {}
        self.protmon_results = {}
        self.is_paused = False
        self.crashing_primitives = {}
        self._crash_synopses = []  # List of crash reports for the current test case

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

        self.server_init()

    def add_node(self, node):
        """
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        @type  node: pGRAPH Node
        @param node: Node to add to session graph
        """

        node.number = len(self.nodes)
        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def add_target(self, target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        @type  target: Target
        @param target: Target to add to session
        """

        # pass specified target parameters to the PED-RPC server.
        target.pedrpc_connect()
        target.set_logger(logger=self.logger)
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

            def callback(session, node, edge, sock)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as session.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet. As another
        example, if you need to fill in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

        @type  src:      str or Request (Node)
        @param src:      Source request name or request node
        @type  dst:      str or Request (Node)
        @param dst:      Destination request name or request node
        @type  callback: def
        @param callback: (Optional, def=None) Callback function to pass received data to between node xmits

        @rtype:  pgraph.Edge
        @return: The edge between the src and dst.
        """

        # if only a source was provided, then make it the destination and set the source to the root node.
        if not dst:
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

        if not self.find_node("name", dst.name):
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
            "skip": self.total_mutant_index,
            "sleep_time": self.sleep_time,
            "restart_sleep_time": self.restart_sleep_time,
            "restart_interval": self.restart_interval,
            "web_port": self.web_port,
            "crash_threshold": self.crash_threshold,
            "total_num_mutations": self.total_num_mutations,
            "total_mutant_index": self.total_mutant_index,
            "netmon_results": self.netmon_results,
            "procmon_results": self.procmon_results,
            "protmon_results": self.protmon_results,
            "is_paused": self.is_paused
        }

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(cPickle.dumps(data, protocol=2)))
        fh.close()

    def fuzz(self):
        """
        Call this routine to get the ball rolling.
        Iterates through and fuzzes all fuzz cases, skipping according to
        self.skip and restarting based on self.restart_interval.

        :return: None
        """
        num_cases_actually_fuzzed = 0
        for fuzz_args in self.fuzz_case_iterator():
            # skip until we pass self.skip
            if self.total_mutant_index <= self.skip:
                continue

            # if we need to pause, do so.
            self.pause()

            # Check restart interval
            if num_cases_actually_fuzzed and num_cases_actually_fuzzed % self.restart_interval == 0:
                self.logger.error("restart interval of %d reached" % self.restart_interval)
                self.restart_target(self.targets[0])

            self.fuzz_current_case(*fuzz_args)

            num_cases_actually_fuzzed += 1

        # If fuzzing is finished, pause thread and wait for a signal.
        # If fuzzing is not finished, web interface thread will catch it. (Does this line still apply?)
        if self.total_mutant_index == self.total_num_mutations:
            helpers.pause_for_signal()

    def fuzz_single_case(self, mutant_index):
        self._reset_fuzz_state()

        fuzz_index = 0
        for fuzz_args in self.fuzz_case_iterator():
            if fuzz_index == mutant_index:
                self.fuzz_current_case(*fuzz_args)
                break
            fuzz_index += 1

    def _reset_fuzz_state(self):
        """
        Restart the object's fuzz state.

        :return: None
        """
        self.total_mutant_index = 0
        if self.fuzz_node:
            self.fuzz_node.reset()

    def fuzz_case_iterator(self, this_node=None, path=()):
        """
        Iterates over fuzz cases and mutates appropriately.
        On each iteration, one may call fuzz_current_case to do the
        actual fuzzing.

        No arguments are necessary as they are both utilized internally
        during the recursive traversal of the session graph.

        @type  this_node: node.Node
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      list
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.

        :raise sex.SullyRuntimeError:
        """
        # if no node is specified, then we start from the root node..
        if not this_node:
            # we can't fuzz if we don't have at least one target and one request.
            if not self.targets:
                raise sex.SullyRuntimeError("No targets specified in session")

            if not self.edges_from(self.root.id):
                raise sex.SullyRuntimeError("No requests specified in session")

            this_node = self.root

        if isinstance(path, tuple):
            path = list(path)

        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # the destination node is the one actually being fuzzed.
            self.fuzz_node = self.nodes[edge.dst]

            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            current_path = " -> ".join([self.nodes[e.src].name for e in path[1:]])
            current_path += " -> %s" % self.fuzz_node.name

            self.logger.info("current fuzz path: %s" % current_path)
            self.logger.info("fuzzed %d of %d total cases" % (self.total_mutant_index, self.total_num_mutations))

            # Loop through and yield all possible mutations of the fuzz node.
            # Note: when mutate() returns False, the node has been reverted to the default (valid) state.
            while self.fuzz_node.mutate():
                self.total_mutant_index += 1
                yield (edge, path)
            self.logger.error("all possible mutations for current fuzz node exhausted")

            # recursively fuzz the remainder of the nodes in the session graph.
            self.fuzz_case_iterator(self.fuzz_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

    def fuzz_current_case(self, edge, path):
        target = self.targets[0]

        # exception error handling routine, print log message and restart target.
        def error_handler(error, msg, error_target, error_sock=None):
            if error_sock:
                error_sock.close()

            msg += "\nException caught: %s" % repr(error)
            msg += "\nRestarting target and trying again"

            self.logger.critical(msg)
            self.restart_target(error_target)

        self.logger.info("fuzzing %d of %d" % (self.fuzz_node.mutant_index,
                                               self.fuzz_node.num_mutations()))
        if self._fuzz_data_logger is not None:
            self._fuzz_data_logger.open_test_case(self.total_mutant_index)

        # attempt to complete a fuzz transmission. keep trying until we are successful, whenever a failure
        # occurs, restart the target.
        while 1:
            # instruct the debugger/sniffer that we are about to send a new fuzz.
            if target.procmon:
                try:
                    target.procmon.pre_send(self.total_mutant_index)
                except Exception, e:
                    error_handler(e, "failed on procmon.pre_send()", target)
                    continue

            if target.netmon:
                try:
                    target.netmon.pre_send(self.total_mutant_index)
                except Exception, e:
                    error_handler(e, "failed on netmon.pre_send()", target)
                    continue

            try:
                target.open()
            except socket.error, e:
                error_handler(e, "socket connection failed", target, target)
                continue

            # if the user registered a pre-send function, pass it the sock and let it do the deed.
            try:
                self.pre_send(target)
            except Exception, e:
                error_handler(e, "pre_send() failed", target, target)
                continue

            # send out valid requests for each node in the current path up to the node we are fuzzing.
            try:
                for e in path[:-1]:
                    node = self.nodes[e.dst]
                    self.transmit(target, node, e)
            except Exception, e:
                error_handler(e, "failed transmitting a node up the path", target, target)
                raise

            # now send the current node we are fuzzing.
            try:
                self.transmit(target, self.fuzz_node, edge)
            except Exception, e:
                error_handler(e, "failed transmitting fuzz node", target, target)
                continue

            # if we reach this point the send was successful for break out of the while(1).
            break

        # if the user registered a post-send function, pass it the sock and let it do the deed.
        # We do this outside the try/except loop because if our fuzz causes a crash then the post_send()
        # will likely fail and we don't want to sit in an endless loop.
        try:
            self.post_send(target)
        except Exception, e:
            error_handler(e, "post_send() failed", target, target)

        # done with the socket.
        target.close()
        # delay in between test cases.
        self.logger.info("sleeping for %f seconds" % self.sleep_time)
        time.sleep(self.sleep_time)
        # poll the PED-RPC endpoints (netmon, procmon etc...) for the target.
        self.poll_pedrpc(target)
        # Log failure(s), restart target, etc.
        self._process_failures(target=target)
        # serialize the current session state to disk.
        self.export_file()

    def import_file(self):
        """
        Load various object values from disk.

        @see: export_file()
        """

        try:
            with open(self.session_filename, "rb") as f:
                data = cPickle.loads(zlib.decompress(f.read()))
        except Exception:
            return

        # update the skip variable to pick up fuzzing from last test case.
        self.skip = data["total_mutant_index"]
        self.session_filename = data["session_filename"]
        self.sleep_time = data["sleep_time"]
        self.restart_sleep_time = data["restart_sleep_time"]
        self.restart_interval = data["restart_interval"]
        self.web_port = data["web_port"]
        self.crash_threshold = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index = data["total_mutant_index"]
        self.netmon_results = data["netmon_results"]
        self.procmon_results = data["procmon_results"]
        self.protmon_results = data["protmon_results"]
        self.is_paused = data["is_paused"]

    # noinspection PyMethodMayBeStatic
    def log(self, msg, level=1):
        raise Exception("Depreciated!")

    def num_mutations(self, this_node=None, path=()):
        """
        Number of total mutations in the graph. The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. The member variable self.total_num_mutations is updated appropriately by this routine.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      list
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.

        @rtype:  int
        @return: Total number of mutations in this session.
        """

        if not this_node:
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

    def pause(self):
        """
        If that pause flag is raised, enter an endless loop until it is lowered.
        """
        while 1:
            if self.is_paused:
                time.sleep(1)
            else:
                break

    def poll_pedrpc(self, target):
        """
        Poll the PED-RPC endpoints (netmon, procmon etc...) for the target.

        @type  target: Target
        @param target: Session target whose PED-RPC services we are polling
        """
        # kill the pcap thread and see how many bytes the sniffer recorded.
        if target.netmon:
            captured_bytes = target.netmon.post_send()
            self.logger.info("netmon captured %d bytes for test case #%d" % (captured_bytes, self.total_mutant_index))
            self.netmon_results[self.total_mutant_index] = captured_bytes

        # check if our fuzz crashed the target. procmon.post_send() returns False if the target access violated.
        if target.procmon and not target.procmon.post_send():
            self.logger.info("procmon detected access violation on test case #%d" % self.total_mutant_index)
            self.log_fail(target.procmon.get_crash_synopsis())

    def log_fail(self, synopsis):
        """
        Log a failure for the current test case.

        @param synopsis: Description of failure.

        @return: None
        """
        self._crash_synopses.append(synopsis)

    def _process_failures(self, target):
        """
        If self.crash_synopses contains any entries, perform these failure-related actions:
         - save failures to self.procmon_results (for website)
         - log failures
         - target restart
         - sys.exit(0) if target restart fails
         - clear self.crash_synopses

        Should be called after each fuzz test case.

        @param target: Target to restart if failure occurred.
        @type target: Target

        @return: None
        """
        if len(self._crash_synopses) > 0:
            self.logger.info("Failure detected on test case #%d" % self.total_mutant_index)

            # retrieve the primitive that caused the crash and increment it's individual crash count.
            self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant, 0) + 1

            # notify with as much information as possible.
            if self.fuzz_node.mutant.name:
                msg = "primitive name: %s, " % self.fuzz_node.mutant.name
            else:
                msg = "primitive lacks a name, "

            msg += "type: %s, default value: %s" % (self.fuzz_node.mutant.s_type, self.fuzz_node.mutant.original_value)
            self.logger.info(msg)

            # print crash synopsis
            if len(self._crash_synopses) > 1:
                # Prepend a header if > 1 failure report, so that they are visible from the main web page
                synopsis = "({0} reports) {1}".format(len(self._crash_synopses), "\n".join(self._crash_synopses))
            else:
                synopsis = "\n".join(self._crash_synopses)
            self.procmon_results[self.total_mutant_index] = synopsis
            self.logger.info(self.procmon_results[self.total_mutant_index].split("\n")[0])

            # if the user-supplied crash threshold is reached, exhaust this node.
            if self.crashing_primitives[self.fuzz_node.mutant] >= self.crash_threshold:
                # as long as we're not a group and not a repeat.
                if not isinstance(self.fuzz_node.mutant, primitives.Group):
                    if not isinstance(self.fuzz_node.mutant, blocks.Repeat):
                        skipped = self.fuzz_node.mutant.exhaust()
                        self.logger.warning(
                            "Crash threshold reached for this primitive, exhausting %d mutants." % skipped
                        )
                        self.total_mutant_index += skipped
                        self.fuzz_node.mutant_index += skipped

            # Clear crash data for next test case
            self._crash_synopses = []

            # start the target back up.
            # If it returns False, stop the test
            if not self.restart_target(target, stop_first=False):
                self.logger.critical("Restarting the target failed, exiting.")
                self.export_file()
                sys.exit(0)

    # noinspection PyMethodMayBeStatic
    def post_send(self, sock):
        """
        Overload or replace this routine to specify actions to run after to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to tear down the RPC request.

        @see: pre_send()

        @type  sock: socket.socket
        @param sock: Connected socket to target
        """

        # default to doing nothing.
        pass

    # noinspection PyMethodMayBeStatic
    def pre_send(self, sock):
        """
        Overload or replace this routine to specify actions to run prior to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        """

        # default to doing nothing.
        pass

    def restart_target(self, target, stop_first=True):
        """
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. Otherwise, do nothing.

        @type  target: session.target
        @param target: Target we are restarting

        @rtype : bool
        @returns: False if restart failed (such that we know it failed). True otherwise.
        """

        # vm restarting is the preferred method so try that first.
        if target.vmcontrol:
            self.logger.warning("restarting target virtual machine")
            target.vmcontrol.restart_target()

        # if we have a connected process monitor, restart the target process.
        elif target.procmon:
            self.logger.warning("restarting target process")
            if stop_first:
                target.procmon.stop_target()

            if not target.procmon.start_target():
                return False

            # give the process a few seconds to settle in.
            time.sleep(3)

        # otherwise all we can do is wait a while for the target to recover on its own.
        else:
            self.logger.error(
                "no vmcontrol or procmon channel available ... sleeping for %d seconds" % self.restart_sleep_time
            )
            time.sleep(self.restart_sleep_time)
            return True

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        target.pedrpc_connect()

        return True

    def server_init(self):
        """
        Called by fuzz() on first run (not on recursive re-entry) to initialize variables, web interface, etc...
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

        # web interface thread doesn't catch KeyboardInterrupt
        # add a signal handler, and exit on SIGINT
        # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon

        # noinspection PyUnusedLocal
        def exit_abruptly(signal_recv, frame_recv):
            """
            Save current settings (just in case) and exit
            """
            self.export_file()
            self.logger.critical("SIGINT received ... exiting")
            sys.exit(0)

        signal.signal(signal.SIGINT, exit_abruptly)

        # spawn the web interface.
        self.web_interface_thread.start()

    def transmit(self, sock, node, edge):
        """
        Render and transmit a node, process callbacks accordingly.

        @type  sock:   socket.socket
        @param sock:   Socket to transmit node on
        @type  node:   pgraph.node.node (Node)
        @param node:   Request/Node to transmit
        @type  edge:   pgraph.edge.edge (pgraph.edge)
        @param edge:   Edge along the current fuzz path from "node" to next node.
        """

        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            data = edge.callback(self, node, edge, sock)

        self.logger.info("Transmitting: [%d.%d]" % (node.id, self.total_mutant_index))

        # if no data was returned by the callback, render the node here.
        if not data:
            data = node.render()

        # Try to send payload down-range
        try:
            self.targets[0].send(data)
            self.last_send = data
        except socket.error, inst:
            self.logger.error("Socket error on send: %s" % inst)

        try:
            # Receive data
            # TODO: Remove magic number (10000)
            self.last_recv = self.targets[0].recv(10000)
        except socket.error, inst:
            self.logger.error("Socket error on receive: %s" % inst)

        # If we have data in our recv buffer
        if self.last_recv:
            self.logger.debug("received: [%d] %s" % (len(self.last_recv), repr(self.last_recv)))
        # Assume a crash?
        else:
            self.logger.warning("Nothing received from target.")
            # Increment individual crash count
            self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant, 0) + 1
            # Note crash information
            self.protmon_results[self.total_mutant_index] = data

    def build_webapp_thread(self, port=26000):
        app.session = self
        http_server = HTTPServer(WSGIContainer(app))
        http_server.listen(port)
        flask_thread = threading.Thread(target=IOLoop.instance().start)
        flask_thread.daemon = True
        return flask_thread
