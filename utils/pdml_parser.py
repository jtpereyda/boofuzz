#!c:\python\python.exe

from __future__ import print_function

import sys
from xml.sax import ContentHandler, make_parser
from xml.sax.handler import feature_namespaces

import six

from boofuzz import helpers


class ParsePDML(ContentHandler):
    def __init__(self):
        ContentHandler.__init__(self)
        self.current = None
        self.start_parsing = False
        self.sulley = ""

    def startElement(self, name, attributes):
        if name == "proto":
            self.current = attributes["name"]

        # if parsing flag is set, we're past tcp
        if self.start_parsing:

            if not name == "field":
                print("Found payload with name %s" % attributes["name"])
            elif name == "field":
                if "value" in list(attributes):
                    val_string = self.get_string(attributes["value"])

                    if val_string:
                        self.sulley += 's_string("%s")\n' % val_string
                        print(self.sulley)
                        # print("\tFound value: %s" % val_string)
                    else:
                        # not string
                        pass
            else:
                raise Exception("WTFException")

    def characters(self, data):
        pass

    def endElement(self, name):
        # if we're closing a packet
        if name == "packet":
            self.start_parsing = False

        # if we're closing a proto tag
        if name == "proto":
            # and that proto is tcp, set parsing flag
            if self.current == "tcp":
                # print("Setting parsing flag to TRUE")
                self.start_parsing = True

            else:
                self.start_parsing = False

    # noinspection PyMethodMayBeStatic
    def get_string(self, parsed):
        # until this becomes more universal, utf-8 is assumed
        parsed = helpers.str_to_bytes(parsed)
        parsed = parsed.replace(b"\t", b"")
        parsed = parsed.replace(b"\r", b"")
        parsed = parsed.replace(b"\n", b"")
        parsed = parsed.replace(b",", b"")
        parsed = parsed.replace(b"0x", b"")
        parsed = parsed.replace(b"\\x", b"")

        value = b""
        while parsed:
            pair = parsed[:2]
            parsed = parsed[2:]

            hex_pair = int(pair, 16)
            if hex_pair > 0x7F:
                return False

            value += six.int2byte(hex_pair)

        value = value.replace(b"\t", b"")
        value = value.replace(b"\r", b"")
        value = value.replace(b"\n", b"")
        value = value.replace(b",", b"")
        value = value.replace(b"0x", b"")
        value = value.replace(b"\\x", b"")

        return value

    # noinspection PyMethodMayBeStatic
    def error(self, exception):
        print("Oh shitz: ", exception)
        sys.exit(1)


if __name__ == "__main__":
    # create the parser object
    parser = make_parser()

    # dont care about xml namespace
    parser.setFeature(feature_namespaces, 0)

    # make the document handler
    handler = ParsePDML()

    # point parser to handler
    parser.setContentHandler(handler)

    # parse
    parser.parse(sys.argv[1])
