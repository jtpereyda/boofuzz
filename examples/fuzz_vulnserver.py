#!/usr/bin/env python3

import argparse
import ipaddress
import sys
from boofuzz import *


"""
Author: Pedro Flor
Date: 10/august/2019
Version: 1.0
"""


def verify_ip(ip_address):
    try:
        return ipaddress.IPv4Address(ip_address)
    except:
        print("ERROR: Invalid IP Address")
        sys.exit(0)


def fuzz_vulnserver(rhost, rport):

    session = Session(
        sleep_time=3,
        target=Target(connection=SocketConnection(str(rhost), rport, proto="tcp")),
    )

    s_initialize("vulnserver_commands")
    s_group(
        "group_vulnserver",
        values=[
            "STATS",
            "RTIME",
            "LTIME",
            "SRUN",
            "TRUN",
            "GMON",
            "GDOG",
            "KSTET",
            "GTER",
            "HTER",
            "LTER",
            "KSTAN",
        ],
    )
    if s_block_start("block_vulnserver", group="group_vulnserver"):
        s_delim(" ", fuzzable=False)
        s_string("AAAA", max_len=3000)
        s_static("\r\n")
    s_block_end("block_vulnserver")

    session.connect(s_get("vulnserver_commands"))
    session.fuzz()


if __name__ == "__main__":

    ### Arguments
    parser = argparse.ArgumentParser(description="_-=Fuzzer=-_")
    parser.add_argument(
        "-r", "--rhost", help="IP Remote Host", metavar="", required=True
    )
    parser.add_argument(
        "-p", "--rport", type=int, help="Remote Port", metavar="", required=True
    )
    args = parser.parse_args()

    ## IP validation
    rhost = verify_ip(args.rhost)
    rport = args.rport

    ## fuzzing
    fuzz_vulnserver(rhost, rport)


"""
TODO
====
1) Monitor the remote service to handle properly the fuzzing process.

How to use the script
=====================
$ python3 ./fuzz_vulnserver.py -r <IP_Address_of_vulnserver> -p 9999
"""
