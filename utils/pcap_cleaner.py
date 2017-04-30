#!c:\\python\\python.exe

import os
import sys
sys.path.append(r"..\..\..\paimei")

from boofuzz import utils

USAGE = "\nUSAGE: pcap_cleaner.py <xxx.crashbin> <path to pcaps>\n"

if len(sys.argv) != 3:
    print USAGE
    sys.exit(1)


#
# generate a list of all test cases that triggered a crash.
#

try:
    crashbin = utils.crash_binning.CrashBinning()
    crashbin.import_file(sys.argv[1])
except Exception:
    print "unable to open crashbin: '%s'." % sys.argv[1]
    sys.exit(1)

test_cases = []
for _, crashes in crashbin.bins.iteritems():
    for crash in crashes:
        test_cases.append("%d.pcap" % crash.extra)

#
# step through the pcap directory and erase all files not pertaining to a crash.
#

for filename in os.listdir(sys.argv[2]):
    if filename not in test_cases:
        os.unlink("%s/%s" % (sys.argv[2], filename))
