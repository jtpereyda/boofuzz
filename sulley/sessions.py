import os
import re
import sys
import zlib
import time
import socket
import httplib
import cPickle
import threading
import BaseHTTPServer
import httplib
import logging

import blocks
import pedrpc
import pgraph
import sex
import primitives


########################################################################################################################
class target:
    '''
    Target descriptor container.
    '''

    def __init__ (self, host, port, **kwargs):
        '''
        @type  host: String
        @param host: Hostname or IP address of target system
        @type  port: Integer
        @param port: Port of target service
        '''

        self.host      = host
        self.port      = port

        # set these manually once target is instantiated.
        self.netmon            = None
        self.procmon           = None
        self.vmcontrol         = None
        self.netmon_options    = {}
        self.procmon_options   = {}
        self.vmcontrol_options = {}


    def pedrpc_connect (self):
        '''
        Pass specified target parameters to the PED-RPC server.
        '''

        # If the process monitor is alive, set it's options
        if self.procmon:
            while 1:
                try:
                    if self.procmon.alive():
                        break
                except:
                    pass

                time.sleep(1)

            # connection established.
            for key in self.procmon_options.keys():
                eval('self.procmon.set_%s(self.procmon_options["%s"])' % (key, key))

        # If the network monitor is alive, set it's options
        if self.netmon:
            while 1:
                try:
                    if self.netmon.alive():
                        break
                except:
                    pass

                time.sleep(1)

            # connection established.
            for key in self.netmon_options.keys():
                eval('self.netmon.set_%s(self.netmon_options["%s"])' % (key, key))


########################################################################################################################
class connection (pgraph.edge.edge):
    def __init__ (self, src, dst, callback=None):
        '''
        Extends pgraph.edge with a callback option. This allows us to register a function to call between node
        transmissions to implement functionality such as challenge response systems. The callback method must follow
        this prototype::

            def callback(session, node, edge, sock)

        Where node is the node about to be sent, edge is the last edge along the current fuzz path to "node", session
        is a pointer to the session instance which is useful for snagging data such as sesson.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet.

        @type  src:      Integer
        @param src:      Edge source ID
        @type  dst:      Integer
        @param dst:      Edge destination ID
        @type  callback: Function
        @param callback: (Optional, def=None) Callback function to pass received data to between node xmits
        '''

        # run the parent classes initialization routine first.
        pgraph.edge.edge.__init__(self, src, dst)

        self.callback = callback


########################################################################################################################
class session (pgraph.graph):
    def __init__(
                  self,
                  session_filename=None,
                  skip=0,
                  sleep_time=1.0,
                  log_level=logging.INFO,
                  logfile=None,
                  logfile_level=logging.DEBUG,
                  proto="tcp",
                  bind=None,
                  restart_interval=0,
                  timeout=5.0,
                  web_port=26000,
                  crash_threshold=3,
                  restart_sleep_time=300
                ):
        '''
        Extends pgraph.graph and provides a container for architecting protocol dialogs.

        @type  session_filename:   String
        @kwarg session_filename:   (Optional, def=None) Filename to serialize persistant data to
        @type  skip:               Integer
        @kwarg skip:               (Optional, def=0) Number of test cases to skip
        @type  sleep_time:         Float
        @kwarg sleep_time:         (Optional, def=1.0) Time to sleep in between tests
        @type  log_level:          Integer
        @kwarg log_level:          (Optional, def=logger.INFO) Set the log level
        @type  logfile:            String
        @kwarg logfile:            (Optional, def=None) Name of log file
        @type  logfile_level:      Integer
        @kwarg logfile_level:      (Optional, def=logger.INFO) Set the log level for the logfile
        @type  proto:              String
        @kwarg proto:              (Optional, def="tcp") Communication protocol ("tcp", "udp", "ssl")
        @type  bind:               Tuple (host, port)
        @kwarg bind:               (Optional, def=random) Socket bind address and port
        @type  timeout:            Float
        @kwarg timeout:            (Optional, def=5.0) Seconds to wait for a send/recv prior to timing out
        @type  restart_interval:   Integer
        @kwarg restart_interval    (Optional, def=0) Restart the target after n test cases, disable by setting to 0
        @type  crash_threshold:    Integer
        @kwarg crash_threshold     (Optional, def=3) Maximum number of crashes allowed before a node is exhaust
        @type  restart_sleep_time: Integer
        @kwarg restart_sleep_time: Optional, def=300) Time in seconds to sleep when target can't be restarted
        @type  web_port:	   Integer
        @kwarg web_port:           (Optional, def=26000) Port for monitoring fuzzing campaign via a web browser	
	'''

        # run the parent classes initialization routine first.
        pgraph.graph.__init__(self)

        self.session_filename    = session_filename
        self.skip                = skip
        self.sleep_time          = sleep_time
        self.proto               = proto.lower()
        self.bind                = bind
        self.ssl                 = False
        self.restart_interval    = restart_interval
        self.timeout             = timeout
        self.web_port            = web_port
        self.crash_threshold     = crash_threshold
        self.restart_sleep_time  = restart_sleep_time

        # Initialize logger
        self.logger = logging.getLogger("Sulley_logger")
        self.logger.setLevel(log_level)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] -> %(message)s')

        if logfile != None:
            filehandler = logging.FileHandler(logfile)
            filehandler.setLevel(logfile_level)
            filehandler.setFormatter(formatter)
            self.logger.addHandler(filehandler)

        consolehandler = logging.StreamHandler()
        consolehandler.setFormatter(formatter)
        consolehandler.setLevel(log_level)
        self.logger.addHandler(consolehandler)

        self.total_num_mutations = 0
        self.total_mutant_index  = 0
        self.fuzz_node           = None
        self.targets             = []
        self.netmon_results      = {}
        self.procmon_results     = {}
        self.protmon_results     = {}
        self.pause_flag          = False
        self.crashing_primitives = {}

        if self.proto == "tcp":
            self.proto = socket.SOCK_STREAM

        elif self.proto == "ssl":
            self.proto = socket.SOCK_STREAM
            self.ssl   = True

        elif self.proto == "udp":
            self.proto = socket.SOCK_DGRAM

        else:
            raise sex.SullyRuntimeError("INVALID PROTOCOL SPECIFIED: %s" % self.proto)

        # import settings if they exist.
        self.import_file()

        # create a root node. we do this because we need to start fuzzing from a single point and the user may want
        # to specify a number of initial requests.
        self.root       = pgraph.node()
        self.root.name  = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv  = None

        self.add_node(self.root)


    ####################################################################################################################
    def add_node (self, node):
        '''
        Add a pgraph node to the graph. We overload this routine to automatically generate and assign an ID whenever a
        node is added.

        @type  node: pGRAPH Node
        @param node: Node to add to session graph
        '''

        node.number = len(self.nodes)
        node.id     = len(self.nodes)

        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node

        return self


    ####################################################################################################################
    def add_target (self, target):
        '''
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        @type  target: session.target
        @param target: Target to add to session
        '''

        # pass specified target parameters to the PED-RPC server.
        target.pedrpc_connect()

        # add target to internal list.
        self.targets.append(target)


    ####################################################################################################################
    def connect (self, src, dst=None, callback=None):
        '''
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
        is a pointer to the session instance which is useful for snagging data such as sesson.last_recv which contains
        the data returned from the last socket transmission and sock is the live socket. A callback is also useful in
        situations where, for example, the size of the next packet is specified in the first packet. As another
        example, if you need to fill in the dynamic IP address of the target register a callback that snags the IP
        from sock.getpeername()[0].

        @type  src:      String or Request (Node)
        @param src:      Source request name or request node
        @type  dst:      String or Request (Node)
        @param dst:      Destination request name or request node
        @type  callback: Function
        @param callback: (Optional, def=None) Callback function to pass received data to between node xmits

        @rtype:  pgraph.edge
        @return: The edge between the src and dst.
        '''

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
        edge = connection(src.id, dst.id, callback)
        self.add_edge(edge)

        return edge


    ####################################################################################################################
    def export_file (self):
        '''
        Dump various object values to disk.

        @see: import_file()
        '''

        if not self.session_filename:
            return

        data = {}
        data["session_filename"]    = self.session_filename
        data["skip"]                = self.total_mutant_index
        data["sleep_time"]          = self.sleep_time
        data["restart_sleep_time"]  = self.restart_sleep_time
        data["proto"]               = self.proto
        data["restart_interval"]    = self.restart_interval
        data["timeout"]             = self.timeout
        data["web_port"]            = self.web_port
        data["crash_threshold"]     = self.crash_threshold
        data["total_num_mutations"] = self.total_num_mutations
        data["total_mutant_index"]  = self.total_mutant_index
        data["netmon_results"]      = self.netmon_results
        data["procmon_results"]     = self.procmon_results
        data['protmon_results']     = self.protmon_results
        data["pause_flag"]          = self.pause_flag

        fh = open(self.session_filename, "wb+")
        fh.write(zlib.compress(cPickle.dumps(data, protocol=2)))
        fh.close()


    ####################################################################################################################
    def fuzz (self, this_node=None, path=[]):
        '''
        Call this routine to get the ball rolling. No arguments are necessary as they are both utilized internally
        during the recursive traversal of the session graph.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.
        '''

        # if no node is specified, then we start from the root node and initialize the session.
        if not this_node:
            # we can't fuzz if we don't have at least one target and one request.
            if not self.targets:
                raise sex.SullyRuntimeError("NO TARGETS SPECIFIED IN SESSION")

            if not self.edges_from(self.root.id):
                raise sex.SullyRuntimeError("NO REQUESTS SPECIFIED IN SESSION")

            this_node = self.root

            try:    self.server_init()
            except: return

        # TODO: complete parallel fuzzing, will likely have to thread out each target
        target = self.targets[0]

        # step through every edge from the current node.
        for edge in self.edges_from(this_node.id):
            # the destination node is the one actually being fuzzed.
            self.fuzz_node = self.nodes[edge.dst]
            num_mutations  = self.fuzz_node.num_mutations()

            # keep track of the path as we fuzz through it, don't count the root node.
            # we keep track of edges as opposed to nodes because if there is more then one path through a set of
            # given nodes we don't want any ambiguity.
            path.append(edge)

            current_path  = " -> ".join([self.nodes[e.src].name for e in path[1:]])
            current_path += " -> %s" % self.fuzz_node.name

            self.logger.info("current fuzz path: %s" % current_path)
            self.logger.info("fuzzed %d of %d total cases" % (self.total_mutant_index, self.total_num_mutations))

            done_with_fuzz_node = False
            crash_count         = 0

            # loop through all possible mutations of the fuzz node.
            while not done_with_fuzz_node:
                # if we need to pause, do so.
                self.pause()

                # if we have exhausted the mutations of the fuzz node, break out of the while(1).
                # note: when mutate() returns False, the node has been reverted to the default (valid) state.
                if not self.fuzz_node.mutate():
                    self.logger.error("all possible mutations for current fuzz node exhausted")
                    done_with_fuzz_node = True
                    continue

                # make a record in the session that a mutation was made.
                self.total_mutant_index += 1

                # if we've hit the restart interval, restart the target.
                if self.restart_interval and self.total_mutant_index % self.restart_interval == 0:
                    self.logger.error("restart interval of %d reached" % self.restart_interval)
                    self.restart_target(target)

                # exception error handling routine, print log message and restart target.
                def error_handler (e, msg, target, sock=None):
                    if sock:
                        sock.close()

                    msg += "\nException caught: %s" % repr(e)
                    msg += "\nRestarting target and trying again"

                    self.logger.critical(msg)
                    self.restart_target(target)

                # if we don't need to skip the current test case.
                if self.total_mutant_index > self.skip:
                    self.logger.info("fuzzing %d of %d" % (self.fuzz_node.mutant_index, num_mutations))

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
                            # establish a connection to the target.
                            sock = socket.socket(socket.AF_INET, self.proto)
                        except Exception, e:
                            error_handler(e, "failed creating socket", target)
                            continue

                        if self.bind:
                            try:
                                sock.bind(self.bind)
                            except Exception, e:
                                error_handler(e, "failed binding on socket", target, sock)
                                continue

                        try:
                            sock.settimeout(self.timeout)
                            # Connect is needed only for TCP stream
                            if self.proto == socket.SOCK_STREAM:
                                sock.connect((target.host, target.port))
                        except Exception, e:
                            error_handler(e, "failed connecting on socket", target, sock)
                            continue

                        # if SSL is requested, then enable it.
                        if self.ssl:
                            try:
                                ssl  = socket.ssl(sock)
                                sock = httplib.FakeSocket(sock, ssl)
                            except Exception, e:
                                error_handler(e, "failed ssl setup", target, sock)
                                continue

                        # if the user registered a pre-send function, pass it the sock and let it do the deed.
                        try:
                            self.pre_send(sock)
                        except Exception, e:
                            error_handler(e, "pre_send() failed", target, sock)
                            continue

                        # send out valid requests for each node in the current path up to the node we are fuzzing.
                        try:
                            for e in path[:-1]:
                                node = self.nodes[e.dst]
                                self.transmit(sock, node, e, target)
                        except Exception, e:
                            error_handler(e, "failed transmitting a node up the path", target, sock)
                            continue

                        # now send the current node we are fuzzing.
                        try:
                            self.transmit(sock, self.fuzz_node, edge, target)
                        except Exception, e:
                            error_handler(e, "failed transmitting fuzz node", target, sock)
                            continue

                        # if we reach this point the send was successful for break out of the while(1).
                        break

                    # if the user registered a post-send function, pass it the sock and let it do the deed.
                    # we do this outside the try/except loop because if our fuzz causes a crash then the post_send()
                    # will likely fail and we don't want to sit in an endless loop.
                    try:
                        self.post_send(sock)
                    except Exception, e:
                        error_handler(e, "post_send() failed", target, sock)

                    # done with the socket.
                    sock.close()

                    # delay in between test cases.
                    self.logger.info("sleeping for %f seconds" % self.sleep_time)
                    time.sleep(self.sleep_time)

                    # poll the PED-RPC endpoints (netmon, procmon etc...) for the target.
                    self.poll_pedrpc(target)

                    # serialize the current session state to disk.
                    self.export_file()

            # recursively fuzz the remainder of the nodes in the session graph.
            self.fuzz(self.fuzz_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        # loop to keep the main thread running and be able to receive signals
        if self.signal_module:
            # wait for a signal only if fuzzing is finished (this function is recursive)
            # if fuzzing is not finished, web interface thread will catch it
            if self.total_mutant_index == self.total_num_mutations:
                import signal
                while True:
                    signal.pause()


    ####################################################################################################################
    def import_file (self):
        '''
        Load varous object values from disk.

        @see: export_file()
        '''

        try:
            fh   = open(self.session_filename, "rb")
            data = cPickle.loads(zlib.decompress(fh.read()))
            fh.close()
        except:
            return

        # update the skip variable to pick up fuzzing from last test case.
        self.skip                = data["total_mutant_index"]

        self.session_filename    = data["session_filename"]
        self.sleep_time          = data["sleep_time"]
        self.restart_sleep_time  = data["restart_sleep_time"]
        self.proto               = data["proto"]
        self.restart_interval    = data["restart_interval"]
        self.timeout             = data["timeout"]
        self.web_port            = data["web_port"]
        self.crash_threshold     = data["crash_threshold"]
        self.total_num_mutations = data["total_num_mutations"]
        self.total_mutant_index  = data["total_mutant_index"]
        self.netmon_results      = data["netmon_results"]
        self.procmon_results     = data["procmon_results"]
        self.protmon_results     = data["protmon_results"]
        self.pause_flag          = data["pause_flag"]


    ####################################################################################################################
    #def log (self, msg, level=1):
        '''
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''
#
        #if self.log_level >= level:
            #print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)


    ####################################################################################################################
    def num_mutations (self, this_node=None, path=[]):
        '''
        Number of total mutations in the graph. The logic of this routine is identical to that of fuzz(). See fuzz()
        for inline comments. The member varialbe self.total_num_mutations is updated appropriately by this routine.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.

        @rtype:  Integer
        @return: Total number of mutations in this session.
        '''

        if not this_node:
            this_node                = self.root
            self.total_num_mutations = 0

        for edge in self.edges_from(this_node.id):
            next_node                 = self.nodes[edge.dst]
            self.total_num_mutations += next_node.num_mutations()

            if edge.src != self.root.id:
                path.append(edge)

            self.num_mutations(next_node, path)

        # finished with the last node on the path, pop it off the path stack.
        if path:
            path.pop()

        return self.total_num_mutations


    ####################################################################################################################
    def pause (self):
        '''
        If thet pause flag is raised, enter an endless loop until it is lowered.
        '''

        while 1:
            if self.pause_flag:
                time.sleep(1)
            else:
                break


    ####################################################################################################################
    def poll_pedrpc (self, target):
        '''
        Poll the PED-RPC endpoints (netmon, procmon etc...) for the target.

        @type  target: session.target
        @param target: Session target whose PED-RPC services we are polling
        '''

        # kill the pcap thread and see how many bytes the sniffer recorded.
        if target.netmon:
            bytes = target.netmon.post_send()
            self.logger.info("netmon captured %d bytes for test case #%d" % (bytes, self.total_mutant_index))
            self.netmon_results[self.total_mutant_index] = bytes

        # check if our fuzz crashed the target. procmon.post_send() returns False if the target access violated.
        if target.procmon and not target.procmon.post_send():
            self.logger.info("procmon detected access violation on test case #%d" % self.total_mutant_index)

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
            self.procmon_results[self.total_mutant_index] = target.procmon.get_crash_synopsis()
            self.logger.info(self.procmon_results[self.total_mutant_index].split("\n")[0])

            # if the user-supplied crash threshold is reached, exhaust this node.
            if self.crashing_primitives[self.fuzz_node.mutant] >= self.crash_threshold:
                # as long as we're not a group and not a repeat.
                if not isinstance(self.fuzz_node.mutant, primitives.group):
                    if not isinstance(self.fuzz_node.mutant, blocks.repeat):
                        skipped = self.fuzz_node.mutant.exhaust()
                        self.logger.warning("crash threshold reached for this primitive, exhausting %d mutants." % skipped)
                        self.total_mutant_index += skipped
                        self.fuzz_node.mutant_index += skipped

            # start the target back up.
            # If it returns False, stop the test
            if self.restart_target(target, stop_first=False) == False:
                self.logger.critical("Restarting the target failed, exiting.")
                self.export_file()
                try:
                    self.thread.join()
                except:
                    self.logger.debug("No server launched")
                sys.exit(0)



    ####################################################################################################################
    def post_send (self, sock):
        '''
        Overload or replace this routine to specify actions to run after to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to tear down the RPC request.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.
        pass


    ####################################################################################################################
    def pre_send (self, sock):
        '''
        Overload or replace this routine to specify actions to run prior to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.
        pass


    ####################################################################################################################
    def restart_target (self, target, stop_first=True):
        '''
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. Otherwise, do nothing.

        @type  target: session.target
        @param target: Target we are restarting
        '''

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
            self.logger.error("no vmcontrol or procmon channel available ... sleeping for %d seconds" % self.restart_sleep_time)
            time.sleep(self.restart_sleep_time)
            # TODO: should be good to relaunch test for crash before returning False
            return False

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        target.pedrpc_connect()


    ####################################################################################################################
    def server_init (self):
        '''
        Called by fuzz() on first run (not on recursive re-entry) to initialize variables, web interface, etc...
        '''

        self.total_mutant_index  = 0
        self.total_num_mutations = self.num_mutations()

        # web interface thread doesn't catch KeyboardInterrupt
        # add a signal handler, and exit on SIGINT
        # TODO: should wait for the end of the ongoing test case, and stop gracefully netmon and procmon
        # TODO: doesn't work on OS where the signal module isn't available
        try:
            import signal
            self.signal_module = True
        except:
            self.signal_module = False
        if self.signal_module:
            def exit_abruptly(signal, frame):
                '''Save current settings (just in case) and exit'''
                self.export_file()
                self.logger.critical("SIGINT received ... exiting")
                try:
                    self.thread.join()
                except:
                    self.logger.debug( "No server launched")

                sys.exit(0)
            signal.signal(signal.SIGINT, exit_abruptly)

        # spawn the web interface.
        self.thread = web_interface_thread(self)
        self.thread.start()


    ####################################################################################################################
    def transmit (self, sock, node, edge, target):
        '''
        Render and transmit a node, process callbacks accordingly.

        @type  sock:   Socket
        @param sock:   Socket to transmit node on
        @type  node:   Request (Node)
        @param node:   Request/Node to transmit
        @type  edge:   Connection (pgraph.edge)
        @param edge:   Edge along the current fuzz path from "node" to next node.
        @type  target: session.target
        @param target: Target we are transmitting to
        '''

        data = None

        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            data = edge.callback(self, node, edge, sock)

        self.logger.info("xmitting: [%d.%d]" % (node.id, self.total_mutant_index))

        # if no data was returned by the callback, render the node here.
        if not data:
            data = node.render()

        # if data length is > 65507 and proto is UDP, truncate it.
        # TODO: this logic does not prevent duplicate test cases, need to address this in the future.
        if self.proto == socket.SOCK_DGRAM:
            # max UDP packet size.
            # TODO: anyone know how to determine this value smarter?
            # - See http://stackoverflow.com/questions/25841/maximum-buffer-length-for-sendto to fix this
            MAX_UDP = 65507

            if os.name != "nt" and os.uname()[0] == "Darwin":
                MAX_UDP = 9216

            if len(data) > MAX_UDP:
                self.logger.debug("Too much data for UDP, truncating to %d bytes" % MAX_UDP)
                data = data[:MAX_UDP]

        try:
            if self.proto == socket.SOCK_STREAM:
                sock.send(data)
            else:
                sock.sendto(data, (self.targets[0].host, self.targets[0].port))
            self.logger.debug("Packet sent : " + repr(data))
        except Exception, inst:
            self.logger.error("Socket error, send: %s" % inst)

        if self.proto == (socket.SOCK_STREAM or socket.SOCK_DGRAM):
            # TODO: might have a need to increase this at some point. (possibly make it a class parameter)
            try:
                self.last_recv = sock.recv(10000)
            except Exception, e:
                self.last_recv = ""
        else:
            self.last_recv = ""

        if len(self.last_recv) > 0:
            self.logger.debug("received: [%d] %s" % (len(self.last_recv), repr(self.last_recv)))
        else:
            self.logger.warning("Nothing received on socket.")
            # Increment individual crash count
            self.crashing_primitives[self.fuzz_node.mutant] = self.crashing_primitives.get(self.fuzz_node.mutant,0) +1
            # Note crash information
            self.protmon_results[self.total_mutant_index] = data ;
            #print self.protmon_results



########################################################################################################################
class web_interface_handler (BaseHTTPServer.BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        self.session = None


    def commify (self, number):
        number     = str(number)
        processing = 1
        regex      = re.compile(r"^(-?\d+)(\d{3})")

        while processing:
            (number, processing) = regex.subn(r"\1,\2",number)

        return number


    def do_GET (self):
        self.do_everything()


    def do_HEAD (self):
        self.do_everything()


    def do_POST (self):
        self.do_everything()


    def do_everything (self):
        if "pause" in self.path:
            self.session.pause_flag = True

        if "resume" in self.path:
            self.session.pause_flag = False

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        if "view_crash" in self.path:
            response = self.view_crash(self.path)
        elif "view_pcap" in self.path:
            response = self.view_pcap(self.path)
        else:
            response = self.view_index()

        self.wfile.write(response)


    def log_error (self, *args, **kwargs):
        pass


    def log_message (self, *args, **kwargs):
        pass


    def version_string (self):
        return "Sulley Fuzz Session"


    def view_crash (self, path):
        test_number = int(path.split("/")[-1])
        return "<html><pre>%s</pre></html>" % self.session.procmon_results[test_number]


    def view_pcap (self, path):
        return path


    def view_index (self):
        response = """
                    <html>
                    <head>
                    <meta http-equiv="refresh" content="5">
                        <title>Sulley Fuzz Control</title>
                        <style>
                            a:link    {color: #FF8200; text-decoration: none;}
                            a:visited {color: #FF8200; text-decoration: none;}
                            a:hover   {color: #C5C5C5; text-decoration: none;}

                            body
                            {
                                background-color: #000000;
                                font-family:      Arial, Helvetica, sans-serif;
                                font-size:        12px;
                                color:            #FFFFFF;
                            }

                            td
                            {
                                font-family:      Arial, Helvetica, sans-serif;
                                font-size:        12px;
                                color:            #A0B0B0;
                            }

                            .fixed
                            {
                                font-family:      Courier New;
                                font-size:        12px;
                                color:            #A0B0B0;
                            }

                            .input
                            {
                                font-family:      Arial, Helvetica, sans-serif;
                                font-size:        11px;
                                color:            #FFFFFF;
                                background-color: #333333;
                                border:           thin none;
                                height:           20px;
                            }
                        </style>
                    </head>
                    <body>
                    <center>
                    <table border=0 cellpadding=5 cellspacing=0 width=750><tr><td>
                    <!-- begin bounding table -->

                    <table border=0 cellpadding=5 cellspacing=0 width="100%%">
                    <tr bgcolor="#333333">
                        <td><div style="font-size: 20px;">Sulley Fuzz Control</div></td>
                        <td align=right><div style="font-weight: bold; font-size: 20px;">%(status)s</div></td>
                    </tr>
                    <tr bgcolor="#111111">
                        <td colspan=2 align="center">
                            <table border=0 cellpadding=0 cellspacing=5>
                                <tr bgcolor="#111111">
                                    <td><b>Total:</b></td>
                                    <td>%(total_mutant_index)s</td>
                                    <td>of</td>
                                    <td>%(total_num_mutations)s</td>
                                    <td class="fixed">%(progress_total_bar)s</td>
                                    <td>%(progress_total)s</td>
                                </tr>
                                <tr bgcolor="#111111">
                                    <td><b>%(current_name)s:</b></td>
                                    <td>%(current_mutant_index)s</td>
                                    <td>of</td>
                                    <td>%(current_num_mutations)s</td>
                                    <td class="fixed">%(progress_current_bar)s</td>
                                    <td>%(progress_current)s</td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <form method=get action="/pause">
                                <input class="input" type="submit" value="Pause">
                            </form>
                        </td>
                        <td align=right>
                            <form method=get action="/resume">
                                <input class="input" type="submit" value="Resume">
                            </form>
                        </td>
                    </tr>
                    </table>

                    <!-- begin procmon results -->
                    <table border=0 cellpadding=5 cellspacing=0 width="100%%">
                        <tr bgcolor="#333333">
                            <td nowrap>Test Case #</td>
                            <td>Crash Synopsis</td>
                            <td nowrap>Captured Bytes</td>
                        </tr>
                    """

        keys = self.session.procmon_results.keys()
        keys.sort()
        for key in keys:
            val   = self.session.procmon_results[key]
            bytes = "&nbsp;"

            if self.session.netmon_results.has_key(key):
                bytes = self.commify(self.session.netmon_results[key])

            response += '<tr><td class="fixed"><a href="/view_crash/%d">%06d</a></td><td>%s</td><td align=right>%s</td></tr>' % (key, key, val.split("\n")[0], bytes)

        response += """
                    <!-- end procmon results -->
                    </table>

                    <!-- end bounding table -->
                    </td></tr></table>
                    </center>
                    </body>
                    </html>
                   """

        # what is the fuzzing status.
        if self.session.pause_flag:
            status = "<font color=red>PAUSED</font>"
        else:
            status = "<font color=green>RUNNING</font>"

        # if there is a current fuzz node.
        if self.session.fuzz_node:
            # which node (request) are we currently fuzzing.
            if self.session.fuzz_node.name:
                current_name = self.session.fuzz_node.name
            else:
                current_name = "[N/A]"

            # render sweet progress bars.
            progress_current     = float(self.session.fuzz_node.mutant_index) / float(self.session.fuzz_node.num_mutations())
            num_bars             = int(progress_current * 50)
            progress_current_bar = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
            progress_current     = "%.3f%%" % (progress_current * 100)

            progress_total       = float(self.session.total_mutant_index) / float(self.session.total_num_mutations)
            num_bars             = int(progress_total * 50)
            progress_total_bar   = "[" + "=" * num_bars + "&nbsp;" * (50 - num_bars) + "]"
            progress_total       = "%.3f%%" % (progress_total * 100)

            response %= \
            {
                "current_mutant_index"  : self.commify(self.session.fuzz_node.mutant_index),
                "current_name"          : current_name,
                "current_num_mutations" : self.commify(self.session.fuzz_node.num_mutations()),
                "progress_current"      : progress_current,
                "progress_current_bar"  : progress_current_bar,
                "progress_total"        : progress_total,
                "progress_total_bar"    : progress_total_bar,
                "status"                : status,
                "total_mutant_index"    : self.commify(self.session.total_mutant_index),
                "total_num_mutations"   : self.commify(self.session.total_num_mutations),
            }
        else:
            response %= \
            {
                "current_mutant_index"  : "",
                "current_name"          : "",
                "current_num_mutations" : "",
                "progress_current"      : "",
                "progress_current_bar"  : "",
                "progress_total"        : "",
                "progress_total_bar"    : "",
                "status"                : "<font color=yellow>UNAVAILABLE</font>",
                "total_mutant_index"    : "",
                "total_num_mutations"   : "",
            }

        return response


########################################################################################################################
class web_interface_server (BaseHTTPServer.HTTPServer):
    '''
    http://docs.python.org/lib/module-BaseHTTPServer.html
    '''

    def __init__(self, server_address, RequestHandlerClass, session):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self.RequestHandlerClass.session = session


########################################################################################################################
class web_interface_thread (threading.Thread):
    def __init__ (self, session):
        threading.Thread.__init__(self, name="SulleyWebServer")

        self._stopevent = threading.Event()
        self.session = session
        self.server  = None


    def run (self):
        self.server = web_interface_server(('', self.session.web_port), web_interface_handler, self.session)
        while not self._stopevent.isSet():
            self.server.handle_request()

    def join(self, timeout=None):
        # A little dirty but no other solution afaik
        self._stopevent.set()
        conn = httplib.HTTPConnection("localhost:%d" % self.session.web_port)
        conn.request("GET", "/")
        conn.getresponse()
