#!/usr/bin/env python3
# Designed for use with boofuzz v0.3.0
#
# Fuzz Testing Autoprogramming
#
# how to run basics: python autoprog.py -a <target ip address> -p <port number>
#


import getopt  # command line arguments
import platform  # For getting the operating system name
import subprocess  # For executing a shell command
import sys
import time
from boofuzz import *
from crc16ccitt import getCrc16Ccitt

mylogger = FuzzLoggerText()
g_target_ip_addr = None
g_autoprogram_port = 65534


# a monitor to verify if the target is still alive
# noinspection PyMethodOverriding
# noinspection PyMethodParameters
class spaceTargetMonitor(NetworkMonitor):
    def alive():
        global g_target_ip_addr
        param = "-n" if platform.system().lower() == "windows" else "-c"
        # Russian Sub Commander Marco Ramius requests one ping only
        command = ["ping", param, "1", g_target_ip_addr]
        # noinspection PyTypeChecker
        message = "alive() sending a ping command to " + g_target_ip_addr
        mylogger.log_info(message)
        try:
            subprocess.run(command, timeout=3)
        except subprocess.TimeoutExpired:
            return False
        else:
            mylogger.log_info("PING success")
            return True

    def pre_send(target=None, fuzz_data_logger=None, session=None, **kwargs):
        return

    def post_send(target=None, fuzz_data_logger=None, session=None, **kwargs):
        return True

    def retrieve_data():
        return

    def start_target():
        return True

    def set_options(*args, **kwargs):
        return

    def get_crash_synopsis():
        return "get_crash_synopsis detected a crash of the target."

    def restart_target(target=None, **kwargs):
        mylogger.log_info("restart_target sleep for 12")
        time.sleep(12)
        if spaceTargetMonitor.alive() is True:
            mylogger.log_info("restart_target ok")
            return True
        else:
            mylogger.log_info("restart_target failed")
            return False

    def post_start_target(target=None, fuzz_data_logger=None, session=None, **kwargs):
        return


def main(argv):
    # parse command line options.
    opts = None
    target_ip_addr = None
    autoprogram_port = 65534
    start_index = 1
    end_index = 65534

    global g_target_ip_addr
    global g_autoprogram_port

    try:
        opts, args = getopt.getopt(argv, "ha:p:s:e:", ["address=", "port=", "start_index=", "end_index="])
    except getopt.GetoptError:
        print(
            "autoprog.py --address|-a <target ip address> --port|-p <auto programming port> --start_index|\
            -s <start of fuzzing index> --end_index|-e <end of fuzzing index>"
        )
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print(
                "autoprog.py --address|-a <target ip address> --port|-p <auto programming port> --start_index|\
                -s <start of fuzzing index> --end_index|-e <end of fuzzing index>"
            )
            sys.exit()
        elif opt in ("-a", "--address"):
            target_ip_addr = arg
        elif opt in ("-p", "--port"):
            autoprogram_port = arg
        elif opt in ("-s", "--startindex"):
            start_index = arg
        elif opt in ("-e", "--endindex"):
            end_index = arg

    g_target_ip_addr = target_ip_addr
    g_autoprogram_port = int(autoprogram_port)
    target_message = "Target device ip address and port " + str(g_target_ip_addr) + " " + str(g_autoprogram_port)
    mylogger.log_info(target_message)

    spaceTargetMonitor(host=g_target_ip_addr, port=g_autoprogram_port)

    mylogger.log_info("Initializing session to target ")
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host=g_target_ip_addr, port=g_autoprogram_port),
            monitors=[spaceTargetMonitor],
        ),
        sleep_time=12,
        crash_threshold_request=2,
        crash_threshold_element=2,
        index_start=int(start_index),
        index_end=int(end_index),
    )
    define_autoprog_static(session=session)
    mylogger.log_info("start fuzzing")

    session.fuzz()


#################################################################
# Single entry configuration within a Proposal list:
#################################################################
# Example protocol which will send the following data in sequence:
#    1. A URL inside of a formatted line
#    2. The checksum of line 1 above.
#    3. A formatted line to indicate the completion of the checksum.
#    4. A formatted line indicating the start of the outer checksum.
#    5. An outer checksum managing data consisting of lines 1,2,3, and 4.
#    6. A formatted line to indicate the completion of the outer checksum.
#
# <ProposalList xmlns="http://www.bbraun.com/HC/AutoProgramming">
# calculated_checksum_value
# </Checksum>
# <ChecksumTotal>
# calculated_outer_checksum_value
# </ChecksumTotal>
#
# An example of what goes out:
#    <ProposalList xmlns="http://www.bbraun.com/HC/AutoProgramming">
#    1234
#    </Checksum>
#    <ChecksumTotal>
#    5678
#    </ChecksumTotal>
#
#################################################################


def define_autoprog_static(session):
    dl_line_1 = String(
        name="proposal_header", default_value='<ProposalList xmlns="http://www.mycompany.com/HC/AutoProgramming">'
    )
    # insert crc here
    dl_line_9 = String(name="crc_end", default_value="</Checksum>", fuzzable=False)
    dl_line_11 = String(name="outer_crc", default_value="<ChecksumTotal>", fuzzable=False)
    # insert outer crc here
    dl_line_12 = String(name="outer_crcend", default_value="</ChecksumTotal>", fuzzable=False)

    reqW = Request("autoprog")
    block = Block(name="autoprogB", request=reqW)
    reqW.push(block)
    crcValue = Checksum(
        name="firstCRC16", block_name="autoprogB", request=reqW, algorithm=getCrc16Ccitt, length=2, fuzzable=False
    )
    crcValue_outer = Checksum(
        name="CRC16_outer", block_name="autoprogB", request=reqW, algorithm=getCrc16Ccitt, length=2, fuzzable=False
    )

    block.push(dl_line_1)
    reqW.push(crcValue)
    block.push(dl_line_9)
    block.push(dl_line_11)
    reqW.push(crcValue_outer)
    block.push(dl_line_12)
    reqW.pop()

    session.connect(reqW)


if __name__ == "__main__":
    main(sys.argv[1:])
