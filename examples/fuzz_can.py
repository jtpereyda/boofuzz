#!/usr/bin/env python3
"""
This sample program implements a boofuzz session for a CAN connection.
The program requires a CAN bus (e.g. a virtual CAN bus vcan0).
The system under test, "icsim" listens to the CAN bus.
"""

from boofuzz import *
import socket
import struct
import time
import can
import scapy
import subprocess
import os
import signal

# def post_test_callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
#    print("Testcase finished")
#    time.sleep(5)
#    return 1


class CanConnection(ITargetConnection):
    """a connection to the virtual CAN bus vcan0"""

    def __init__(self, interface="vcan0", can_id=0x123):
        self.interface = interface
        self.can_id = can_id
        self.is_alive = False

    def open(self):
        """Open CAN raw socket"""
        # self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        # self.sock.bind((self.interface,))
        # TODO check if interface exists
        self.bus = can.Bus(interface="socketcan", channel="vcan0", bitrate=500000)
        self.is_alive = True

    def info(self):
        """Return a short description for boofuzz logs/UI."""
        return f"Raw CAN Socket on interface {self.interface}"

    def close(self):
        """Close CAN socket"""
        print(f"bus {self.interface} is going down")
        self.is_alive = False
        if self.bus:
            self.bus.shutdown()
        self.bus = None

    def send(self, data):
        """
        `data` is the fuzzed payload and contains the CAN frame containing:
        - arbitration ID (aka "CAN ID"),
        - data length code (dlc)
        - data (payload_bytes)
        No padding is employed if not modeled in the Protocol Definition.
        """
        # Extract fuzzed fields
        can_id = struct.unpack("<I", data[0:4])[0]
        dlc = data[4]
        payload = data[5 : 5 + dlc].ljust(8, b"\x00")
        # print(f"[{can_id}] {payload}")

        # create the CAN frame (using can-utils)
        msg = can.Message(arbitration_id=self.can_id, data=payload, dlc=dlc, is_extended_id=False)

        self.bus.send(msg)

    def recv(self, max_bytes=4096):
        """Return CAN responses (if any)."""
        try:
            # print("retrieving response")
            response = self.bus.recv(timeout=0.01)
            return response
        except socket.timeout:
            # print("nothing received")
            return b""

        return b""

    def alive(self):
        """Tell boofuzz whether our connection is alive."""
        return self.is_alive

    def __repr__(self):
        return f"CAN Connection interace={self.interface}"


class MyProcessMonitor(BaseMonitor):
    """
    a custom process monitor that checks icsim's PID
    We don't reuse the existing ones, because we can't check a TCP port.
    """

    def __init__(self, cmd, args, cwd=None):
        super().__init__()
        self.failure_code = 0
        self.cmd = [cmd] + args
        print(f"monitor for {self.cmd}")
        self.proc = None
        self.cwd = cwd
        self.last_result = None
        self.soft_fail = False
        # We expect the target as running
        # self.start_target()

    def check_proc(self):
        if self.proc is None:
            print("no proc")
            return False

        print(f"proc {self.proc.pid}")
        try:
            os.kill(self.proc.pid, 0)
            return True
        except ProcessLookupError:
            return False  # No such process
        except PermissionError:
            return True  # Process exists but no permission
        # ret = self.proc.poll()
        # if ret is None:
        #    return True # process is ready
        return False

    def alive(self):
        print("is alive?")
        return True

    def start_target(self, *args, **kwargs):
        print(f"starting target {self.cmd}")
        proc = subprocess.Popen(
            self.cmd, cwd=self.cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
        )
        time.sleep(2)
        # while True:
        #    # wait until the process reacts
        #    if self.proc.poll() is None: break
        #    # TODO maybe wait?
        print("ready")
        self.proc = proc

        return True

    def stop_target(self, *args, **kwargs):
        print(f"stopping process {self.proc.pid}")
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)  # killpg
                time.sleep(0.5)
            except Exception as e:
                print(f"[!] Failed to terminate process: {e}")

        return True

    def restart_target(self, *args, **kwargs):
        print("restart_target")
        self.stop_target()
        self.start_target()

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        self.soft_fail_code = 0

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        response = target._target_connection.recv()
        print("POST SEND")
        if response:
            print(f"got a response {response}")
            print(response.data)
            self.get_crash_synopsis()
            self.last_result = "BAD_RESPONSE"
            fuzz_data_logger.log_info("CAN message received")
            self.soft_fail_code = 42
            return False

        # check if process is still running
        if self.proc and self.proc.poll() is not None:
            return False

        return True

    def teardown(self):
        """stop process with destructor"""
        print("teardown!")
        self.stop_target()
        super().stop_target()

    def __repr__(self):
        return f"Process Monitor {self.cmd}"


class BitSweep(Byte):
    """Custom protocol definition for a single bit"""

    def __init__(
        self, name=None, default_value="", size=None, padding=b"\x00", encoding="utf-8", max_len=None, *args, **kwargs
    ):
        super(Byte, self).__init__(name=name, default_value=default_value, *args, **kwargs)

    def mutations(self, default_value):
        yield 0x80  # b10000000
        yield 0x40  # b01000000
        yield 0x20  # b00100000
        yield 0x10  # b00010000
        yield 0x8  # b00001000
        yield 0x4  # b00000100
        yield 0x2  # b00000010
        yield 0x1  # b00000001


def post_test_case(target, fuzz_data_logger, session, *args, **kwargs):
    """soft crash in case of a CAN network reply"""
    for monitor in target.monitors:
        code = getattr(monitor, "soft_fail_code", 0)
        if code:
            # Log as "failure" so web UI sees it
            fuzz_data_logger.log_fail(f"Soft fail code: {code}")
            # Immediately mark target alive again to prevent restart
            if hasattr(target, "_alive"):
                target._alive = True
            # Reset soft_fail_code for next testcase
            monitor.soft_fail_code = 0


def main():
    process_monitor = MyProcessMonitor(
        cmd="/home/kali/ACOSec/ICSim/icsim", args=["vcan0"], cwd="/home/kali/ACOSec/ICSim"
    )

    conn = CanConnection(interface="vcan0", can_id=0x188)

    target = Target(connection=conn, monitors=[process_monitor])

    session = Session(target=target, sleep_time=0.01, reuse_target_connection=True)
    session.register_post_test_case_callback(post_test_case)

    # CAN message structure using the new protocol defintion
    request = Request(
        "can_frame",
        children=(
            DWord("can_id", 0x188, fuzzable=False),
            Byte("dlc", 8, fuzzable=False),
            # Byte("data", 8)
            # BitSweep("data")
            Block(
                "data",
                children=(
                    BitSweep("data_0", 0x00),
                    BitSweep("data_1", 0x00),
                    BitSweep("data_2", 0x00),
                    BitSweep("data_3", 0x00),
                    #    Byte("data_0", 0x00),
                    #    Byte("data_1", 0x01),
                    #    Byte("data_2", 0x02),
                    #    #s_byte(name="data_3")
                    #    #BitField(name="data_3", width=8, max_num=22),
                    #    Byte("data_3", 0x03),
                    #    Byte("data_4", 0x04),
                    #    Byte("data_5", 0x05),
                    #    Byte("data_6", 0x06),
                    #    Byte("data_7", 0x07),
                    #    Byte("data_8", 0x08),
                ),
            ),
        ),
    )

    session.connect(request)  # , callback=post_test_callback)

    try:
        session.fuzz()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Exiting gracefully.")
    except Exception as e:
        print(e)
    finally:
        process_monitor.teardown()


if __name__ == "__main__":
    main()
