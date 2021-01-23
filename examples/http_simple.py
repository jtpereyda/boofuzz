#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

# More advanced request definitions can be found in the request_definitions directory.

from boofuzz import *


def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("127.0.0.1", 80)),
    )

    define_proto(session=session)

    session.fuzz()


def define_proto(session):
    # disable Black formatting to keep custom indentation
    # fmt: off
    req = Request("HTTP-Request", children=(
        Block("Request-Line", children=(
            Group(name="Method", values=["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"]),
            Delim(name="space-1", default_value=" "),
            String(name="URI", default_value="/index.html"),
            Delim(name="space-2", default_value=" "),
            String(name="HTTP-Version", default_value="HTTP/1.1"),
            Static(name="CRLF", default_value="\r\n"),
        )),
        Block("Host-Line", children=(
            String(name="Host-Key", default_value="Host:"),
            Delim(name="space", default_value=" "),
            String(name="Host-Value", default_value="example.com"),
            Static(name="CRLF", default_value="\r\n"),
        )),
        Static(name="CRLF", default_value="\r\n"),
    ))
    # fmt: on

    session.connect(req)


def define_proto_static(session):
    s_initialize(name="Request")
    with s_block("Request-Line"):
        s_group("Method", ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
        s_delim(" ", name="space-1")
        s_string("/index.html", name="Request-URI")
        s_delim(" ", name="space-2")
        s_string("HTTP/1.1", name="HTTP-Version")
        s_static("\r\n", name="Request-Line-CRLF")
        s_string("Host:", name="Host-Line")
        s_delim(" ", name="space-3")
        s_string("example.com", name="Host-Line-Value")
        s_static("\r\n", name="Host-Line-CRLF")
    s_static("\r\n", "Request-CRLF")

    session.connect(s_get("Request"))


if __name__ == "__main__":
    main()
