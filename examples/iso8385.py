#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0
#
# Fuzz iso8385 protocol
# Author Fakhir Karim Reda
# kf@cyber-defense.ma / www.cyber-defense.ma

import os

from boofuzz import *


def recordlength(s):
    pad = 4 - (len(s) % 4)
    if pad == 4:
        pad = 0
    s = "0" * pad + s
    return s


s_initialize("allrandom")

if s_block_start("singlebitmapnaive"):
    s_random(
        "30 33 32 37 49 53 4F 37 30 31 30 30 30 30 30 31 31 31 30 F6 F3 00 21 8E E1 A0 08 00 00 00 00 00 00 00 01 31 "
        "36 34 32 36 30 30 30 30 30 30 31 35 31 30 33 33 35 31 37 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 "
        "30 30 30 30 30 30 30 31 30 30 30 31 37 30 39 32 37 32 31 35 33 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 "
        "31 30 30 30 39 32 37 31 39 31 31 31 35 31 32 30 30 30 30 31 36 30 34 30 31 31 31 32 31 36 30 36 35 30 30 30 "
        "32 30 30 36 30 30 30 30 30 31 30 32 30 36 38 37 30 31 39 31 31 39 31 35 38 34 30 31 39 30 39 32 30 30 31 30 "
        "30 30 33 32 30 30 30 30 30 31 35 30 30 30 30 30 30 33 34 30 42 41 4E 41 4E 41 20 52 45 50 55 42 4C 49 43 20 "
        "20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54 59 20 50 52 30 36 32 50 38 37 30 30 31 34 50 32 "
        "35 30 30 31 33 50 38 38 30 30 31 34 50 35 34 30 30 31 52 50 39 35 30 30 32 30 31 50 36 38 30 32 30 30 33 30 "
        "30 30 39 32 37 30 32 30 36 38 37 30 31 39 31 31 39 38 34 30 38 34 30 30 30 39 30 33 39 30 30 33 39 30 39 36 "
        "30 43 30 46 31 31 39",
        min_length=331,
        max_length=350,
        fuzzable=True,
        num_mutations=500,
    )
s_block_end()


s_initialize("littlestatic")

if s_block_start("singlebitmapverynaive"):
    s_binary("30 33 32 37")  # size + 3byte of header
    s_random(
        "49 53 4F 37 30 31 30 30 30 30 30 31 31 31 30 F6 F3 00 21 8E E1 A0 08 00 00 00 00 00 00 00 01 31 36 34 32 36 "
        "30 30 30 30 30 30 31 35 31 30 33 33 35 31 37 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 "
        "30 30 30 31 30 30 30 31 37 30 39 32 37 32 31 35 33 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 31 30 30 30 "
        "39 32 37 31 39 31 31 31 35 31 32 30 30 30 30 31 36 30 34 30 31 31 31 32 31 36 30 36 35 30 30 30 32 30 30 36 "
        "30 30 30 30 30 31 30 32 30 36 38 37 30 31 39 31 31 39 31 35 38 34 30 31 39 30 39 32 30 30 31 30 30 30 33 32 "
        "30 30 30 30 30 31 35 30 30 30 30 30 30 33 34 30 42 41 4E 41 4E 41 20 52 45 50 55 42 4C 49 43 20 20 20 20 20 "
        "20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54 59 20 50 52 30 36 32 50 38 37 30 30 31 34 50 32 35 30 30 31 "
        "33 50 38 38 30 30 31 34 50 35 34 30 30 31 52 50 39 35 30 30 32 30 31 50 36 38 30 32 30 30 33 30 30 30 39 32 "
        "37 30 32 30 36 38 37 30 31 39 31 31 39 38 34 30 38 34 30 30 30 39 30 33 39 30 30 33 39 30 39 36 30 43 30 46 "
        "31 31 39",
        min_length=331,
        max_length=331,
        fuzzable=True,
        num_mutations=500,
    )
s_block_end()

# fuzz just financial datas
s_initialize("iso8583ng")

if s_block_start("eltsize", encoder=recordlength):
    s_size("elements", length=2, endian=">", fuzzable=False)  # size
s_block_end()
if s_block_start("elements"):
    s_binary("49 53 4F 37 30 31 30 30 30 30")  # header
    s_binary("30 31 31 31")  # MTI
    s_random(
        "30 F6 F3 00 21 8E E1 A0 08 00 00 00 00 00 00 00 01 31 36 34 32 36 30 30 30 30 30 30 31 35 31 30 33 33 35 31 "
        "37 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 31 37 30 39 32 37 32 "
        "31 35 33 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 31 30 30 30 39 32 37 31 39 31 31 31 35 31 32 30 30 30 "
        "30 31 36 30 34 30 31 31 31 32 31 36 30 36 35 30 30 30 32 30 30 36 30 30 30 30 30 31 30 32 30 36 38 37 30 31 "
        "39 31 31 39 31 35 38 34 30 31 39 30 39 32 30 30 31 30 30 30 33 32 30 30 30 30 30 31 35 30 30 30 30 30 30 33 "
        "34 30 42 41 4E 41 4E 41 20 52 45 50 55 42 4C 49 43 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 "
        "20 54 59 20 50 52 30 36 32 50 38 37 30 30 31 34 50 32 35 30 30 31 33 50 38 38 30 30 31 34 50 35 34 30 30 31 "
        "52 50 39 35 30 30 32 30 31 50 36 38 30 32 30 30 33 30 30 30 39 32 37 30 32 30 36 38 37 30 31 39 31 31 39 38 "
        "34 30 38 34 30 30 30 39 30 33 39 30 30 33 39 30 39 36 30 43 30 46 31 31 39",
        min_length=331,
        max_length=350,
        fuzzable=True,
        num_mutations=500,
    )
s_block_end()

# Fuzz all iso8385 payloads

s_initialize("nastyiso")

if s_block_start("eltsize", encoder=recordlength):
    s_size("elements", length=2, endian=">", fuzzable=False)
s_block_end()

if s_block_start("elements"):
    s_random("49 53 4F 37 30 31 30 30 30 30", min_length=10, max_length=10, num_mutations=50, fuzzable=True)  # header
    s_random("30 31 31 31", min_length=4, max_length=4, num_mutations=50, fuzzable=True)  # MTI
    s_random("30 F6 F3 00 21 8E E1 A0", min_length=8, max_length=16, num_mutations=100, fuzzable=True)  # BITMAP
    s_random(
        "08 00 00 00 00 00 00 00 01 31 36 34 32 36 30 30 30 30 30 30 31 35 31 30 33 33 35 31 37 30 30 30 30 30 30 30 "
        "30 30 30 30 30 31 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 31 37 30 39 32 37 32 31 35 33 30 30 30 30 30 "
        "30 30 31 30 30 30 30 30 30 30 31 30 30 30 39 32 37 31 39 31 31 31 35 31 32 30 30 30 30 31 36 30 34 30 31 31 "
        "31 32 31 36 30 36 35 30 30 30 32 30 30 36 30 30 30 30 30 31 30 32 30 36 38 37 30 31 39 31 31 39 31 35 38 34 "
        "30 31 39 30 39 32 30 30 31 30 30 30 33 32 30 30 30 30 30 31 35 30 30 30 30 30 30 33 34 30 42 41 4E 41 4E 41 "
        "20 52 45 50 55 42 4C 49 43 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54 59 20 50 52 30 36 "
        "32 50 38 37 30 30 31 34 50 32 35 30 30 31 33 50 38 38 30 30 31 34 50 35 34 30 30 31 52 50 39 35 30 30 32 30 "
        "31 50 36 38 30 32 30 30 33 30 30 30 39 32 37 30 32 30 36 38 37 30 31 39 31 31 39 38 34 30 38 34 30 30 30 39 "
        "30 33 39 30 30 33 39 30 39 36 30 43 30 46 31 31 39",
        min_length=305,
        max_length=600,
        fuzzable=True,
        num_mutations=100,
    )
s_block_end()


mysession_filename = "audits\\iso8385.session2"

# remove session filename if exists
if os.path.isfile(mysession_filename):
    os.remove(mysession_filename)

target_ip = "8.8.8.8"
start_cmd = ["MYDI_SID", "030001"]

sess = Session(session_filename=mysession_filename, crash_threshold_element=20)

target = Target(connection=TCPSocketConnection(target_ip, 6771))
target.netmon = pedrpc.Client("127.0.0.1", 26001)
target.procmon = pedrpc.Client(target_ip, 26013)
target.procmon_options = {
    "proc_name": "BANK_SID 030001",
    "start_commands": ["/usr/bin/startsid"],
    "stop_commands": ["/usr/bin/killsid"],
}
sess.add_target(target)


sess.connect(s_get("allrandom"))
sess.connect(s_get("littlestatic"))
sess.connect(s_get("iso8583ng"))
sess.connect(s_get("nastyiso"))


sess.fuzz()
