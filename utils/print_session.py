#! /usr/bin/python

import sys
import zlib
import cPickle

USAGE = "\nUSAGE: print_session.py <session file>\n"

if len(sys.argv) != 2:
    print USAGE
    sys.exit(1)

fh = open(sys.argv[1], "rb")
data = cPickle.loads(zlib.decompress(fh.read()))
fh.close()


#print data
for key in data.keys():
    print key + " -> " + str(data[key])

