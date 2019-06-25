#! /usr/bin/python

import pickle
import sys
import zlib
from io import open

USAGE = "\nUSAGE: print_session.py <session file>\n"

if len(sys.argv) != 2:
    print(USAGE)
    sys.exit(1)

fh = open(sys.argv[1], "rb")
data = pickle.loads(zlib.decompress(fh.read()))
fh.close()


# print data
for key in list(data):
    print(key + " -> " + str(data[key]))
