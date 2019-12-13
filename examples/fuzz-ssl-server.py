#!/usr/bin/env python2
# designed for use with boofuzz
#
# minimal example which fuzzes a remote HTTPS server
# use this as a starting point for SSL/TLS server fuzzing

from boofuzz import *

# If you don't want to verify remote certificate, create a SSLContext.
# WARNING: You will be vulnerable to a man-in-the-middle attack!
#   import ssl
#   ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
#   ctx.check_hostname = False
#   ctx.verify_mode = ssl.CERT_NONE

session = Session(
    target=Target(
        connection=SSLSocketConnection(
            host="google.de",
            port=443,
            server_hostname="google.de",
            # sslcontext=ctx,
        )
    )
)
s_initialize("GET Request")
s_string("GET", name="request method")
s_delim(" ")
s_string("/", name="resource")
s_static("\r\n\r\n")
session.connect(session.root, s_get("GET Request"))
session.fuzz()
