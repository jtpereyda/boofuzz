from boofuzz import *

# All HTTP requests that I could think of/find

# List of all blocks defined here (for easy copy/paste)
"""
sess.connect(s_get("HTTP VERBS"))
sess.connect(s_get("HTTP METHOD"))
sess.connect(s_get("HTTP REQ"))
"""


# Fuzz all the publicly avalible methods known for HTTP Servers

s_initialize("HTTP VERBS")
s_group("verbs", values=["GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND", "CONNECT", "PROPPATCH",
                         "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN",
                         "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", "MKACTIVITY",
                         "ORDERPATCH", "ACL", "PATCH", "SEARCH", "CAT"])
if s_block_start("body", group="verbs"):
    s_delim(" ")
    s_delim("/")
    s_string("index.html")
    s_delim(" ")
    s_string("HTTP")
    s_delim("/")
    s_int(1, output_format="ascii")
    s_delim(".")
    s_int(1, output_format="ascii")
    s_static("\r\n\r\n")
s_block_end()


# Fuzz the HTTP Method itself

s_initialize("HTTP METHOD")
s_string("FUZZ")
s_static(" /index.html HTTP/1.1")
s_static("\r\n\r\n")


# Fuzz this standard multi-header HTTP request
# GET / HTTP/1.1
# Host: www.google.com
# Connection: keep-alive
# User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.83 Safari/537.1
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
# Accept-Encoding: gzip,deflate,sdch
# Accept-Language: en-US,en;q=0.8
# Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3

s_initialize("HTTP REQ")
s_static("GET / HTTP/1.1\r\n")
# Host: www.google.com
s_static("Host")
s_delim(":")
s_delim(" ")
s_string("www.google.com")
s_static("\r\n")
# Connection: keep-alive
s_static("Connection")
s_delim(":")
s_delim(" ")
s_string("Keep-Alive")
# User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.83 Safari/537.1
s_static("User-Agent")
s_delim(":")
s_delim(" ")
s_string("Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.83 Safari/537.1")
s_static("\r\n")
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
s_static("Accept")
s_delim(":")
s_delim(" ")
s_string("text")
s_delim("/")
s_string("html")
s_delim(",")
s_string("application")
s_delim("/")
s_string("xhtml")
s_delim("+")
s_string("xml")
s_delim(",")
s_string("application")
s_delim("/")
s_string("xml")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(9, output_format="ascii")
s_delim(",")
s_string("*")
s_delim("/")
s_string("*")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(8, output_format="ascii")
s_static("\r\n")
# Accept-Encoding: gzip,deflate,sdch
s_static("Accept-Encoding")
s_delim(":")
s_delim(" ")
s_string("gzip")
s_delim(",")
s_string("deflate")
s_delim(",")
s_string("sdch")
s_static("\r\n")
# Accept-Language: en-US,en;q=0.8
s_static("Accept-Language")
s_delim(":")
s_delim(" ")
s_string("en-US")
s_delim(",")
s_string("en")
s_delim(";")
s_string("q")
s_delim("=")
s_string("0.8")
s_static("\r\n")
# Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
s_static("Accept-Charset")
s_delim(":")
s_delim(" ")
s_string("ISO")
s_delim("-")
s_int(8859, output_format="ascii")
s_delim("-")
s_int(1, output_format="ascii")
s_delim(",")
s_string("utf-8")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(7, output_format="ascii")
s_delim(",")
s_string("*")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(3, output_format="ascii")
s_static("\r\n\r\n")
