import sys
import time
import unittest
from multiprocessing import Process

from boofuzz.monitors import NetworkMonitor, pedrpc, ProcessMonitor

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

    def set_foobar(self, value):
        self.foobar = value

    def get_foobar(self):
        return self.foobar


def _start_rpc(server):
    server.serve_forever()


# https://github.com/jtpereyda/boofuzz/pull/409
@unittest.skipIf(
    sys.platform.startswith("win") and sys.version_info.major == 2, "Multithreading problem on Python2 Windows"
)
class TestProcessMonitor(unittest.TestCase):
    def setUp(self):
        self.rpc_server = MockRPCServer(RPC_HOST, RPC_PORT)

        self.rpc_server_process = Process(target=_start_rpc, args=(self.rpc_server,))
        self.rpc_server_process.start()
        time.sleep(0.01)  # give the RPC server some time to start up

        self.process_monitor = ProcessMonitor(RPC_HOST, RPC_PORT)

    def tearDown(self):
        self.rpc_server.stop()
        self.rpc_server_process.terminate()

        self.rpc_server = None
        self.rpc_server_process = None
        self.process_monitor = None

    def test_process_monitor_alive(self):
        self.assertEqual(self.process_monitor.alive(), True)

        self.process_monitor.stop()
        self.rpc_server_process.join()

        self.assertEqual(self.rpc_server_process.exitcode, 0)

    def test_set_options(self):
        self.assertEqual(self.process_monitor.get_foobar(), "barbaz")

        self.process_monitor.set_options(foobar="bazbar")

        self.assertEqual(self.process_monitor.get_foobar(), "bazbar")

    def test_set_options_persistent(self):
        self.process_monitor.set_options(foobar="bazbar")

        self.rpc_server.stop()
        self.rpc_server_process.terminate()
        self.rpc_server = MockRPCServer(RPC_HOST, RPC_PORT)
        self.rpc_server_process = Process(target=_start_rpc, args=(self.rpc_server,))
        self.rpc_server_process.start()
        time.sleep(0.01)  # give the RPC server some time to start up

        self.assertEqual(self.process_monitor.alive(), True)
        self.assertEqual(self.process_monitor.get_foobar(), "bazbar")


# https://github.com/jtpereyda/boofuzz/pull/409
@unittest.skipIf(
    sys.platform.startswith("win") and sys.version_info.major == 2, "Multithreading problem on Python2 Windows"
)
class TestNetworkMonitor(unittest.TestCase):
    def setUp(self):
        self.rpc_server = MockRPCServer(RPC_HOST, RPC_PORT)

        self.rpc_server_process = Process(target=_start_rpc, args=(self.rpc_server,))
        self.rpc_server_process.start()
        time.sleep(0.01)  # give the RPC server some time to start up

        self.network_monitor = NetworkMonitor(RPC_HOST, RPC_PORT)

    def tearDown(self):
        self.rpc_server.stop()
        self.rpc_server_process.terminate()

        self.rpc_server = None
        self.rpc_server_process = None
        self.network_monitor = None

    def test_network_monitor_alive(self):
        self.assertEqual(self.network_monitor.alive(), True)

        self.network_monitor.stop()
        self.rpc_server_process.join()

        self.assertEqual(self.rpc_server_process.exitcode, 0)


if __name__ == "__main__":
    unittest.main()
