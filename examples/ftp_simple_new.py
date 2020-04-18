#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

from boofuzz import *


def main():
    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 2121)))

    user = Request("user", children=(
        String("key", "USER"),
        Delim("space", " "),
        String("val", "anonymous"),
        Static("end", "\r\n"),
    ))

    passw = Request("pass", children=(
        String("key", "PASS"),
        Delim("space", " "),
        String("val", "james"),
        Static("end", "\r\n"),
    ))

    stor = Request("stor", children=(
        String("key", "STOR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

    retr = Request("retr", children=(
        String("key", "RETR"),
        Delim("space", " "),
        String("val", "AAAA"),
        Static("end", "\r\n"),
    ))

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)

    session.fuzz()


if __name__ == "__main__":
    main()
