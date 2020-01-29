#!c:\\python\\python.exe

#
# pedram amini <pamini@tippingpoint.com>
#
# this was a really half assed fuzz. someone should take it further, see my notes in the requests file for more info.
#

from boofuzz import Session, Target, s_get

# noinspection PyUnresolvedReferences
# pytype: disable=import-error
from request_definitions import trend  # noqa: F401

# pytype: enable=import-error


sess = Session(session_filename="audits/trend_server_protect_20901.session", sleep_time=0.25, log_level=10)
sess.add_target(Target("192.168.181.2", 20901))

sess.connect(s_get("20901"))
sess.fuzz()
