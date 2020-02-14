#!/usr/bin/env python3
# Designed for use with boofuzz v0.1.7

from boofuzz import *


def main():
    session = Session(target=Target(connection=SocketConnection("127.0.0.1", 80, proto="tcp")),)

    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
        s_delim(" ", name="space-1")
        s_string("/index.html", name="Request-URI")
        s_delim(" ", name="space-2")
        s_string("HTTP/1.1", name="HTTP-Version")
        s_static("\r\n", name="Request-Line-CRLF")
        s_static("Content-Length:", name="Content-Length-Header")
        s_delim(" ", name="space-3")
        s_size("Body-Content", output_format="ascii", name="Content-Length-Value")
    s_static("\r\n", "Request-CRLF")

    with s_block("Body-Content"):
        s_string("Body content ...", name="Body-Content-Value")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
