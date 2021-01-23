#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

from boofuzz import *


def main():
    """
    This example is a very simple FTP fuzzer. It uses no process monitory
    (procmon) and assumes that the FTP server is already running.
    """
    session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 21)))

    define_proto(session=session)

    session.fuzz()


def define_proto(session):
    # disable Black formatting to keep custom indentation
    # fmt: off
    user = Request("user", children=(
        String(name="key", default_value="USER"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="anonymous"),
        Static(name="end", default_value="\r\n"),
    ))

    passw = Request("pass", children=(
        String(name="key", default_value="PASS"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="james"),
        Static(name="end", default_value="\r\n"),
    ))

    stor = Request("stor", children=(
        String(name="key", default_value="STOR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    retr = Request("retr", children=(
        String(name="key", default_value="RETR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))
    # fmt: on

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)


def define_proto_static(session):
    """Same protocol, using the static definition style."""
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


if __name__ == "__main__":
    main()
