#!c:\\python\\python.exe

#
# pedram amini <pamini@tippingpoint.com>
#
# on vmware:
#     cd shared\sulley\branches\pedram
#     process_monitor.py -c audits\trend_server_protect_5168.crashbin -p SpntSvc.exe
#     network_monitor.py -d 1 -f "src or dst port 5168" -p audits\trend_server_protect_5168
#
# on localhost:
#     vmcontrol.py -r "c:\Progra~1\VMware\VMware~1\vmrun.exe" -x "v:\vmfarm\images\windows\2000\win_2000_pro-clones\TrendM~1\win_2000_pro.vmx" --snapshot "sulley ready and waiting"
#
# this key gets written which fucks trend service even on reboot.
# HKEY_LOCAL_MACHINE\SOFTWARE\TrendMicro\ServerProtect\CurrentVersion\Engine
#
# uncomment the req/num to do a single test case.
#

import time

from sulley   import *
from requests import trend

req = num = None
#req = "5168: op-3"
#num = "\x04"

def rpc_bind (sock):
    bind = utils.dcerpc.bind("25288888-bd5b-11d1-9d53-0080c83a5c2c", "1.0")
    sock.send(bind)

    utils.dcerpc.bind_ack(sock.recv(1000))


def do_single (req, num):
    import socket

    # connect to the server.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.181.133", 5168))

    # send rpc bind.
    rpc_bind(s)

    request = s_get(req)

    while 1:
        if request.names["subs"].value == num:
            break

        s_mutate()

    print "xmitting single test case"
    s.send(s_render())
    print "done."


def do_fuzz ():
    sess   = sessions.session(session_filename="audits/trend_server_protect_5168.session")
    target = sessions.target("192.168.181.133", 5168)

    target.netmon    = pedrpc.client("192.168.181.133", 26001)
    target.procmon   = pedrpc.client("192.168.181.133", 26002)
    target.vmcontrol = pedrpc.client("127.0.0.1",       26003)

    target.procmon_options = \
    {
        "proc_name"      : "SpntSvc.exe",
        "stop_commands"  : ['net stop "trend serverprotect"'],
        "start_commands" : ['net start "trend serverprotect"'],
    }

    # start up the target.
    target.vmcontrol.restart_target()

    print "virtual machine up and running"

    sess.add_target(target)
    sess.pre_send = rpc_bind
    sess.connect(s_get("5168: op-1"))
    sess.connect(s_get("5168: op-2"))
    sess.connect(s_get("5168: op-3"))
    sess.connect(s_get("5168: op-5"))
    sess.connect(s_get("5168: op-a"))
    sess.connect(s_get("5168: op-1f"))
    sess.fuzz()

    print "done fuzzing. web interface still running."


if not req or not num:
    do_fuzz()
else:
    do_single(req, num)