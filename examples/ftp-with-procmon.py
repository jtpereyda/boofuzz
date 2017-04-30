#!/usr/bin/env python
# Designed for use with boofuzz v0.0.8
from boofuzz import *


def main():
    """
    This example is a very simple FTP fuzzer using a process monitor (procmon).
    It assumes that the procmon is already running. The script will connect to
    the procmon and tell the procmon to start the target application
    (see start_cmd).
    
    The ftpd.py in `start_cmd` is a simple FTP server using pyftpdlib. You can
    substitute any FTP server.
    """
    target_ip = "127.0.0.1"
    start_cmd = ['python', 'C:\\ftpd\\ftpd.py']
    session = Session(
        target=Target(
            connection=SocketConnection(target_ip, 21, proto='tcp'),
            procmon=pedrpc.Client(target_ip, 26002),
            procmon_options={"start_commands": [start_cmd]}
        ),
        sleep_time=1,
    )

    s_initialize("user")
    s_string("USER")
    s_delim(" ")
    s_string("anonymous")
    s_static("\r\n")

    s_initialize("pass")
    s_string("PASS")
    s_delim(" ")
    s_string("james")
    s_static("\r\n")

    s_initialize("stor")
    s_string("STOR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    s_initialize("retr")
    s_string("RETR")
    s_delim(" ")
    s_string("AAAA")
    s_static("\r\n")

    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.connect(s_get("pass"), s_get("stor"))
    session.connect(s_get("pass"), s_get("retr"))

    session.fuzz()


if __name__ == "__main__":
    main()
