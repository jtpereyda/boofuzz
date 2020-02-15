#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0

# Original author:
#
# pedram amini <pamini@tippingpoint.com>
#
# on vmware:
#     cd shared\boofuzz\branches\pedram
#     network_monitor.py -d 1 -f "src or dst port 5298" -p audits\trillian_jabber
#     process_monitor.py -c audits\trillian_jabber.crashbin -p trillian.exe
#
# on localhost:
#     vmcontrol.py -r "c:\Progra~1\VMware\VMware~1\vmrun.exe" \
#                  -x "v:\vmfarm\images\windows\xp\win_xp_pro-clones\allsor~1\win_xp_pro.vmx" \
#                  --snapshot "boofuzz ready and waiting"
#
# note:
#     you MUST register the IP address of the fuzzer as a valid MDNS "presence" host. to do so, simply install and
#     launch trillian on the fuzz box with rendezvous enabled. otherwise the target will drop the connection.
#

from boofuzz import pedrpc, s_get, sessions, TCPSocketConnection

# noinspection PyUnresolvedReferences
# pytype: disable=import-error
from request_definitions import jabber  # noqa: F401

# pytype: enable=import-error


def init_message(sock):
    init = '<?xml version="1.0" encoding="UTF-8" ?>\n'
    init += '<stream:stream to="152.67.137.126" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams">'

    sock.send(init)
    sock.recv(1024)


sess = sessions.Session(session_filename="audits/trillian.session")
target = sessions.Target(connection=TCPSocketConnection("152.67.137.126", 5298))
target.netmon = pedrpc.Client("152.67.137.126", 26001)
target.procmon = pedrpc.Client("152.67.137.126", 26002)
target.vmcontrol = pedrpc.Client("127.0.0.1", 26003)
target.procmon_options = {"proc_name": "trillian.exe"}

# start up the target.
target.vmcontrol.restart_target()
print("virtual machine up and running")

sess.add_target(target)
sess.pre_send = init_message
sess.connect(sess.root, s_get("chat message"))
sess.fuzz()
