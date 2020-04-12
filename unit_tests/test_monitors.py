import sys
import time
import unittest
from multiprocessing import Process

from boofuzz.monitors import pedrpc, ProcessMonitor

RPC_HOST = "localhost"
RPC_PORT = 31337


# noinspection PyMethodMayBeStatic
class MockRPCServer(pedrpc.Server):
    def __init__(self, host, port):
        super(MockRPCServer, self).__init__(host, port)
        self.foobar = "barbaz"

    def alive(self):
        print("alive!")
        return True

    def get_crash_synopsis(self):
        return "YES"

    def post_send(self):
        return True

    def pre_send(self, index):
        assert index is not None

        return

    def restart_target(self):
        return True

    def retrieve_data(self):
        return b"YES"

    def set_test(self, value):
        assert value is not None

        return

    def start_target(self):
        return True

    def stop_target(self):
        return True

    def shutdown_rpc(self):
        sys.exit(0)

    def set_foobar(self, value):
        self.foobar = value

    def get_foobar(self):
        return self.foobar


def _start_rpc(host, port):
    server = MockRPCServer(host, port)
    server.serve_forever()


class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.rpc_server = Process(target=_start_rpc, args=(RPC_HOST, RPC_PORT))
        self.rpc_server.start()

        time.sleep(0.2)  # give the RPC server some time to start up

    def tearDown(self):
        self.rpc_server.terminate()

    def test_process_monitor_alive(self):

        process_monitor = ProcessMonitor(RPC_HOST, RPC_PORT)

        self.assertEqual(process_monitor.alive(), True)

        process_monitor.shutdown_rpc()

        self.rpc_server.join()

        self.assertEqual(self.rpc_server.exitcode, 0)

    def test_set_options(self):

        process_monitor = ProcessMonitor(RPC_HOST, RPC_PORT)

        self.assertEqual(process_monitor.get_foobar(), "barbaz")

        process_monitor.set_options(foobar="bazbar")

        self.assertEqual(process_monitor.get_foobar(), "bazbar")

    def test_set_options_persistant(self):

        process_monitor = ProcessMonitor(RPC_HOST, RPC_PORT)

        process_monitor.set_options(foobar="bazbar")

        self.rpc_server.terminate()
        self.rpc_server = Process(target=_start_rpc, args=(RPC_HOST, RPC_PORT))
        self.rpc_server.start()
        time.sleep(0.2)

        self.assertEqual(process_monitor.alive(), True)
        self.assertEqual(process_monitor.get_foobar(), "bazbar")


class TestNetworkMonitor(unittest.TestCase):
    def setUp(self):
        self.rpc_server = Process(target=_start_rpc, args=(RPC_HOST, RPC_PORT))
        self.rpc_server.start()

        time.sleep(0.2)  # give the RPC server some time to start up

    def tearDown(self):
        self.rpc_server.terminate()

    def test_network_monitor_alive(self):
        network_monitor = ProcessMonitor(RPC_HOST, RPC_PORT)

        self.assertEqual(network_monitor.alive(), True)

        network_monitor.shutdown_rpc()

        self.rpc_server.join()
        self.assertEqual(self.rpc_server.exitcode, 0)
