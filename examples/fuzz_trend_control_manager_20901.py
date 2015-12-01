#!c:\\python\\python.exe

#
# pedram amini <pamini@tippingpoint.com>
#
# this was a really half assed fuzz. someone should take it further, see my notes in the requests file for more info.
#

from boofuzz import *
# noinspection PyUnresolvedReferences
from requests import trend


sess = sessions.Session(session_filename="audits/trend_server_protect_20901.session", sleep_time=.25, log_level=10)
sess.add_target(sessions.Target("192.168.181.2", 20901))

sess.connect(s_get("20901"))
sess.fuzz()
