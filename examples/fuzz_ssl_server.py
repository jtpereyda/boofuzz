#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0
#
# Minimal example which fuzzes a remote HTTPS server
# Use this as a starting point for SSL/TLS server fuzzing

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
            host="127.0.0.1",
            port=443,
            server_hostname="example.com",  # Hostname must match the remote certificate
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
