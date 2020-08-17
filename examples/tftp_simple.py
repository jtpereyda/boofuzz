#!/usr/bin/env python
from boofuzz import *


def main():

    port = 69
    host = "127.0.0.1"
    protocol = "udp"

    session = Session(target=Target(connection=SocketConnection(host, port, proto=protocol),),)

    s_initialize("RRQ")
    s_static("\x00\x01")
    s_string("filename")
    s_static("\x00")
    s_static("netascii")
    s_static("\x00")

    s_initialize("WRQ")
    s_static("\x00\x02")
    s_string("filename")
    s_static("\x00")
    s_static("netascii")
    s_static("\x00")

    s_initialize("TRQ")
    s_static("\x00\x02")
    s_string("filename")
    s_static("\x00")
    s_static("mail")
    s_static("\x00")

    session.connect(s_get("WRQ"))
    # session.connect(s_get("RRQ"))

    session.fuzz()


if __name__ == "__main__":

    main()
