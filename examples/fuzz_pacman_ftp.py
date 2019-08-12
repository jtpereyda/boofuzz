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
        print ("ERROR: Invalid IP Address")
        sys.exit(0)



def fuzz_pcman_ftp(rhost,rport):

    session = Session (sleep_time=0,log_level=100,
        target=Target(
            connection = SocketConnection(str(rhost),rport, proto='tcp')))

    s_initialize("user")
    s_static("USER anonymous\r\n")
    s_static("PASSWORD guest\r\n")
    s_static("SYST\r\n")
    s_delim(" ",fuzzable=False)
    s_string("AAAA",max_len=3000)
    s_static("\r\n")

    session.connect(s_get("user"))
    

    session.fuzz()

if __name__ == "__main__":
    
    ### Arguments
    parser = argparse.ArgumentParser(description='_-=Fuzzer=-_')
    parser.add_argument('-r', '--rhost', help="IP Remote Host", metavar='', required=True)
    parser.add_argument('-p', '--rport', type=int, help="Remote Port", metavar='', required=True)
    args = parser.parse_args()

    ## IP validation
    rhost = verify_ip(args.rhost)
    rport = args.rport

    ## fuzzing
    fuzz_pcman_ftp(rhost, rport)
    


"""
TODO
====
1) Monitor the remote service to handle properly the fuzzing process.

How to use the script:
======================
a) Download  and run "PCMan FTP Server 2.0.7" on WinXP
   Download: https://www.exploit-db.com/apps/9fceb6fefd0f3ca1a8c36e97b6cc925d-PCMan.7z
b) Run the script in you Linux box
   $ python3 ./fuzz_pacman_ftp.py -r 172.16.103.129 -p 21


"""
