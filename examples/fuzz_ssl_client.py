#!/usr/bin/env python3
# Designed for use with boofuzz v0.2.0
#
# Minimal example which act as a TLS server
# It will listen on localhost and fuzz the connecting TLS client

import ssl

from boofuzz import *

# In order to act as a SSL/TLS server, boofuzz requires a SSL/TLS
# certificate. You can create a self-signed one with
#    openssl req -x509 -newkey rsa -keyout key.pem -out cert.pem -days 365 -nodes
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

session = Session(
    target=Target(connection=SSLSocketConnection(host="127.0.0.1", port=443, sslcontext=ctx, server=True))
)
s_initialize("A")
s_string("A")
session.connect(session.root, s_get("A"))
session.fuzz()
