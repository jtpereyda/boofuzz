#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

# Original author:
#
# pedram amini <pamini@tippingpoint.com>
#
# this was a really half assed fuzz. someone should take it further, see my notes in the requests file for more info.
#

from boofuzz import s_get, Session, Target, TCPSocketConnection

# noinspection PyUnresolvedReferences
# pytype: disable=import-error
from request_definitions import trend  # noqa: F401

# pytype: enable=import-error


sess = Session(session_filename="audits/trend_server_protect_20901.session", sleep_time=0.25)
sess.add_target(Target(connection=TCPSocketConnection("127.0.0.1", 20901)))

sess.connect(s_get("20901"))
sess.fuzz()
