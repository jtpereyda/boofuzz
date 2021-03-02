#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

from boofuzz import *


def main():
    port = 69
    host = "127.0.0.1"

    session = Session(
        target=Target(
            connection=UDPSocketConnection(host, port),
        ),
    )

    s_initialize("RRQ")
    s_static("\x00\x01")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_string("netascii", name="Mode")
    s_static("\x00")

    s_initialize("WRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_string("netascii", name="Mode")
    s_static("\x00")

    s_initialize("TRQ")
    s_static("\x00\x02")
    s_string("filename", name="Filename")
    s_static("\x00")
    s_static("mail")
    s_static("\x00")

    session.connect(s_get("RRQ"))
    session.connect(s_get("WRQ"))
    session.connect(s_get("TRQ"))

    session.fuzz()


if __name__ == "__main__":
    main()
