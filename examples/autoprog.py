#!/usr/bin/env python3
# Designed for use with boofuzz v0.3.0
#
# Autoprogramming an Internet Of Things (IOT) device by sending it a formatted xml data file with internal
# checksum over selected portions of the data.
# A typical CRC 16 algorithm is used to manage data integrity.
#
# how to run: python autoprog.py -a <target ip address> -p <port number>
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


# Verify if the IOT target is still alive by expecting a response to a ping. This means that the test must have
# network access to the same subnet as the IOT device target. Verify that a ping reply is successful independent of
# running this fuzz test.
#
# noinspection PyMethodOverriding
# noinspection PyMethodParameters
class IOT_TargetMonitor(NetworkMonitor):
    def alive():
        global g_target_ip_addr
        param = "-n" if platform.system().lower() == "windows" else "-c"
        # One ping only
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

    # The use of a 12 second sleep is based on experimentation for a specific IOT device. Change the number of seconds
    # as needed for your environment.
    def restart_target(target=None, **kwargs):
        mylogger.log_info("restart_target sleep for 12")
        time.sleep(12)
        if IOT_TargetMonitor.alive() is True:
            mylogger.log_info("restart_target ok")
            return True
        else:
            mylogger.log_info("restart_target failed")
            return False

    def post_start_target(target=None, fuzz_data_logger=None, session=None, **kwargs):
        return


def main(argv):
    # parse command line options.
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

    IOT_TargetMonitor(host=g_target_ip_addr, port=g_autoprogram_port)

    mylogger.log_info("Initializing session to target ")
    session = Session(
        target=Target(
            connection=TCPSocketConnection(host=g_target_ip_addr, port=g_autoprogram_port),
            monitors=[IOT_TargetMonitor],
        ),
        # The use of a 12 second sleep is based on experimentation for a specific IOT device. Change the sleep count
        # as needed for your environment.
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
# An Autoprogramming proposal protocol example
#################################################################
# Example protocol which will send the following data in sequence:
#    1. A URL inside a formatted line
#    2. The checksum of line 1.
#    3. A formatted line to indicate the completion of the checksum.
#    4. A formatted line indicating the start of the outer checksum.
#    5. An outer checksum managing data consisting of lines 1,2,3, and 4.
#    6. A formatted line to indicate the completion of the outer checksum.
#
# <ProposalList xmlns="http://www.example.com/HC/AutoProgramming">
# the_calculated_checksum_value_of_previous_line
# </Checksum_section_end>
# <ChecksumTotal_begins>
# the_calculated_outer_checksum_value
# </ChecksumTotal_ends>
#
# An example of an AutoProgram protocol output:
#    <ProposalList xmlns="http://www.example.com/HC/AutoProgramming">
#    1234
#    </Checksum_section_end>
#    <ChecksumTotal_begins>
#    5678
#    </ChecksumTotal_ends>
#
#################################################################


def define_autoprog_static(session):
    dl_line_1 = String(
        name="proposal_header", default_value='<ProposalList xmlns="http://www.mycompany.com/HC/AutoProgramming">'
    )
    # insert inner crc here
    dl_line_2 = String(name="crc_end", default_value="</Checksum_end>", fuzzable=False)
    dl_line_3 = String(name="outer_crc", default_value="<ChecksumTotal_begins>", fuzzable=False)
    # insert outer crc here
    dl_line_4 = String(name="outer_crcend", default_value="</ChecksumTotal_ends>", fuzzable=False)

    reqW = Request("autoprog")
    block = Block(name="autoprogB", request=reqW)
    reqW.push(block)
    crcValue_inner = Checksum(
        name="firstCRC16", block_name="autoprogB", request=reqW, algorithm=getCrc16Ccitt, length=2, fuzzable=False
    )
    crcValue_outer = Checksum(
        name="CRC16_outer", block_name="autoprogB", request=reqW, algorithm=getCrc16Ccitt, length=2, fuzzable=False
    )

    block.push(dl_line_1)
    reqW.push(crcValue_inner)
    block.push(dl_line_2)
    block.push(dl_line_3)
    reqW.push(crcValue_outer)
    block.push(dl_line_4)
    reqW.pop()

    session.connect(reqW)


if __name__ == "__main__":
    main(sys.argv[1:])
