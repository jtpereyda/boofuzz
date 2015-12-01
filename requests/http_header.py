from boofuzz import *

# List of all HTTP Headers I could find

# List of all blocks defined here (for easy copy/paste)
"""
sess.connect(s_get("HTTP HEADER ACCEPT"))
sess.connect(s_get("HTTP HEADER ACCEPTCHARSET"))
sess.connect(s_get("HTTP HEADER ACCEPTDATETIME"))
sess.connect(s_get("HTTP HEADER ACCEPTENCODING"))
sess.connect(s_get("HTTP HEADER ACCEPTLANGUAGE"))
sess.connect(s_get("HTTP HEADER AUTHORIZATION"))
sess.connect(s_get("HTTP HEADER CACHECONTROL"))
sess.connect(s_get("HTTP HEADER CLOSE"))
sess.connect(s_get("HTTP HEADER CONTENTLENGTH"))
sess.connect(s_get("HTTP HEADER CONTENTMD5"))
sess.connect(s_get("HTTP HEADER COOKIE"))
sess.connect(s_get("HTTP HEADER DATE"))
sess.connect(s_get("HTTP HEADER DNT"))
sess.connect(s_get("HTTP HEADER EXPECT"))
sess.connect(s_get("HTTP HEADER FROM"))
sess.connect(s_get("HTTP HEADER HOST"))
sess.connect(s_get("HTTP HEADER IFMATCH"))
sess.connect(s_get("HTTP HEADER IFMODIFIEDSINCE"))
sess.connect(s_get("HTTP HEADER IFNONEMATCH"))
sess.connect(s_get("HTTP HEADER IFRANGE"))
sess.connect(s_get("HTTP HEADER IFUNMODIFIEDSINCE"))
sess.connect(s_get("HTTP HEADER KEEPALIVE"))
sess.connect(s_get("HTTP HEADER MAXFORWARDS"))
sess.connect(s_get("HTTP HEADER PRAGMA"))
sess.connect(s_get("HTTP HEADER PROXYAUTHORIZATION"))
sess.connect(s_get("HTTP HEADER RANGE"))
sess.connect(s_get("HTTP HEADER REFERER"))
sess.connect(s_get("HTTP HEADER TE"))
sess.connect(s_get("HTTP HEADER UPGRADE"))
sess.connect(s_get("HTTP HEADER USERAGENT"))
sess.connect(s_get("HTTP HEADER VIA"))
sess.connect(s_get("HTTP HEADER WARNING"))
sess.connect(s_get("HTTP HEADER XATTDEVICEID"))
sess.connect(s_get("HTTP HEADER XDONOTTRACK"))
sess.connect(s_get("HTTP HEADER XFORWARDEDFOR"))
sess.connect(s_get("HTTP HEADER XREQUESTEDWITH"))
sess.connect(s_get("HTTP HEADER XWAPPROFILE"))
"""


# Fuzz Accept header
# Accept: text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5

s_initialize("HTTP HEADER ACCEPT")
s_static("GET / HTTP/1.1\r\n")
s_static("Accept")
s_delim(":")
s_delim(" ")
s_string("text")
s_delim("/")
s_string("*")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(3, output_format="ascii")
s_delim(",")
s_delim(" ")
s_string("text")
s_delim("/")
s_string("html")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(7, output_format="ascii")
s_delim(",")
s_delim(" ")
s_string("text")
s_delim("/")
s_string("html")
s_delim(";")
s_string("level")
s_delim("=")
s_string("1")
s_delim(",")
s_delim(" ")
s_string("text")
s_delim("/")
s_string("html")
s_delim(";")
s_string("level")
s_delim("=")
s_int(2, output_format="ascii")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(4, output_format="ascii")
s_delim(",")
s_delim(" ")
s_string("*")
s_delim("/")
s_string("*")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(5, output_format="ascii")
s_static("\r\n\r\n")


# Fuzz Accept-Charset header
# Accept-Charset: utf-8, unicode-1-1;q=0.8

s_initialize("HTTP HEADER ACCEPTCHARSET")
s_static("GET / HTTP/1.1\r\n")
s_static("Accept-Charset")
s_delim(":")
s_delim(" ")
s_string("utf")
s_delim("-")
s_int(8, output_format="ascii")
s_delim(",")
s_delim(" ")
s_string("unicode")
s_delim("-")
s_int(1, output_format="ascii")
s_delim("-")
s_int(1, output_format="ascii")
s_delim(";")
s_string("q")
s_delim("=")
s_int(0, output_format="ascii")
s_delim(".")
s_int(8, output_format="ascii")
s_static("\r\n\r\n")


# Fuzz Accept-Datetime header
# Accept-Datetime: Thu, 31 May 2007 20:35:00 GMT

s_initialize("HTTP HEADER ACCEPTDATETIME")
s_static("GET / HTTP/1.1\r\n")
s_static("Accept-Datetime")
s_delim(":")
s_delim(" ")
s_string("Thu")
s_delim(",")
s_delim(" ")
s_string("31")
s_delim(" ")
s_string("May")
s_delim(" ")
s_string("2007")
s_delim(" ")
s_string("20")
s_delim(":")
s_string("35")
s_delim(":")
s_string("00")
s_delim(" ")
s_string("GMT")
s_static("\r\n\r\n")


# Fuzz Accept-Encoding header
# Accept-Encoding: gzip, deflate

s_initialize("HTTP HEADER ACCEPTENCODING")
s_static("GET / HTTP/1.1\r\n")
s_static("Accept-Encoding")
s_delim(":")
s_delim(" ")
s_string("gzip")
s_delim(", ")
s_string("deflate")
s_static("\r\n\r\n")


# Fuzz Accept-Language header
# Accept-Language: en-us, en;q=0.5

s_initialize("HTTP HEADER ACCEPTLANGUAGE")
s_static("GET / HTTP/1.1\r\n")
s_static("Accept-Language")
s_delim(":")
s_delim(" ")
s_string("en-us")
s_delim(",")
s_string("en")
s_delim(";")
s_string("q")
s_delim("=")
s_string("0.5")
s_static("\r\n\r\n")


# Fuzz Authorization header
# Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
s_initialize("HTTP HEADER AUTHORIZATION")
s_static("GET / HTTP/1.1\r\n")
s_static("Authorization")
s_delim(":")
s_delim(" ")
s_string("Basic")
s_delim(" ")
s_string("QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
s_static("\r\n\r\n")


# Fuzz Cache-Control header
# Cache-Control: no-cache
s_initialize("HTTP HEADER CACHECONTROL")
s_static("GET / HTTP/1.1\r\n")
s_static("Cache-Control")
s_delim(":")
s_delim(" ")
s_string("no")
s_delim("-")
s_string("cache")
s_static("\r\n\r\n")


# Fuzz Connection header
# Connection: close
s_initialize("HTTP HEADER CLOSE")
s_static("GET / HTTP/1.1\r\n")
s_static("Connection")
s_delim(":")
s_delim(" ")
s_string("close")
s_static("\r\n\r\n")


# Fuzz Content Length header
# Content-Length: 348
s_initialize("HTTP HEADER CONTENTLENGTH")
s_static("GET / HTTP/1.1\r\n")
s_static("Content-Length")
s_delim(":")
s_delim(" ")
s_string("348")
s_static("\r\n\r\n")


# Fuzz Content MD5 header
# Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==
s_initialize("HTTP HEADER CONTENTMD5")
s_static("GET / HTTP/1.1\r\n")
s_static("Content-MD5")
s_delim(":")
s_delim(" ")
s_string("Q2hlY2sgSW50ZWdyaXR5IQ==")
s_static("\r\n\r\n")


# Fuzz COOKIE header
# Cookie: PHPSESSIONID=hLKQPySBvyTRq5K5RJmcTHQVtQycmwZG3Qvr0tSy2w9mQGmbJbJn;
s_initialize("HTTP HEADER COOKIE")
s_static("GET / HTTP/1.1\r\n")

if s_block_start("cookie"):
    s_static("Cookie")
    s_delim(":")
    s_delim(" ")
    s_string("PHPSESSIONID")
    s_delim("=")
    s_string("hLKQPySBvyTRq5K5RJmcTHQVtQycmwZG3Qvr0tSy2w9mQGmbJbJn")
    s_static(";")
    s_static("\r\n")
    s_block_end()

s_repeat("cookie", max_reps=5000, step=500)
s_static("\r\n\r\n")


# Fuzz Date header
# Date: Tue, 15 Nov 2012 08:12:31 EST
s_initialize("HTTP HEADER DATE")
s_static("GET / HTTP/1.1\r\n")
s_static("Date")
s_delim(":")
s_delim(" ")
s_string("Tue")
s_delim(",")
s_delim(" ")
s_string("15")
s_delim(" ")
s_string("Nov")
s_delim(" ")
s_string("2012")
s_delim(" ")
s_string("08")
s_delim(":")
s_string("12")
s_delim(":")
s_string("31")
s_delim(" ")
s_string("EST")
s_static("\r\n\r\n")


# Fuzz DNT header -> May be same as X-Do-Not-Track?
# DNT: 1
s_initialize("HTTP HEADER DNT")
s_static("GET / HTTP/1.1\r\n")
s_static("DNT")
s_delim(":")
s_delim(" ")
s_string("1")
s_static("\r\n\r\n")


# Fuzz Expect header
# Expect: 100-continue
s_initialize("HTTP HEADER EXPECT")
s_static("GET / HTTP/1.1\r\n")
s_static("Expect")
s_delim(":")
s_delim(" ")
s_string("100")
s_delim("-")
s_string("continue")
s_static("\r\n\r\n")


# Fuzz From header
# From: derp@derp.com
s_initialize("HTTP HEADER FROM")
s_static("GET / HTTP/1.1\r\n")
s_static("From")
s_delim(":")
s_delim(" ")
s_string("derp")
s_delim("@")
s_string("derp")
s_delim(".")
s_string("com")
s_static("\r\n\r\n")


# Fuzz Host header
# Host: 127.0.0.1
s_initialize("HTTP HEADER HOST")
s_static("GET / HTTP/1.1\r\n")
s_static("Host")
s_delim(":")
s_delim(" ")
s_string("127.0.0.1")
s_static("\r\n")
s_string("Connection")
s_delim(":")
s_delim(" ")
s_string("Keep-Alive")
s_static("\r\n\r\n")


# Fuzz If-Match header
# If-Match: "737060cd8c284d8af7ad3082f209582d"
s_initialize("HTTP HEADER IFMATCH")
s_static("GET / HTTP/1.1\r\n")
s_static("If-Match")
s_delim(":")
s_delim(" ")
s_static("\"")
s_string("737060cd8c284d8af7ad3082f209582d")
s_static("\"")
s_static("\r\n\r\n")


# Fuzz If-Modified-Since header
# If-Modified-Since: Sat, 29 Oct 2012 19:43:31 ESTc
s_initialize("HTTP HEADER IFMODIFIEDSINCE")
s_static("GET / HTTP/1.1\r\n")
s_static("If-Modified-Since")
s_delim(":")
s_delim(" ")
s_string("Sat")
s_delim(",")
s_delim(" ")
s_string("29")
s_delim(" ")
s_string("Oct")
s_delim(" ")
s_string("2012")
s_delim(" ")
s_string("08")
s_delim(":")
s_string("12")
s_delim(":")
s_string("31")
s_delim(" ")
s_string("EST")
s_static("\r\n\r\n")


# Fuzz If-None-Match header
# If-None-Match: "737060cd8c284d8af7ad3082f209582d"
s_initialize("HTTP HEADER IFNONEMATCH")
s_static("GET / HTTP/1.1\r\n")
s_static("If-None-Match")
s_delim(":")
s_delim(" ")
s_static("\"")
s_string("737060cd8c284d8af7ad3082f209582d")
s_static("\"")
s_static("\r\n\r\n")


# Fuzz If-Range header
# If-Range: "737060cd8c284d8af7ad3082f209582d"
s_initialize("HTTP HEADER IFRANGE")
s_static("GET / HTTP/1.1\r\n")
s_static("If-Range")
s_delim(":")
s_delim(" ")
s_static("\"")
s_string("737060cd8c284d8af7ad3082f209582d")
s_static("\"")
s_static("\r\n\r\n")


# Fuzz If-Unmodified-Since header
# If-Unmodified-Since: Sat, 29 Oct 2012 19:43:31 EST
s_initialize("HTTP HEADER IFUNMODIFIEDSINCE")
s_static("GET / HTTP/1.1\r\n")
s_static("If-Unmodified-Since")
s_delim(":")
s_delim(" ")
s_string("Sat")
s_delim(",")
s_delim(" ")
s_string("29")
s_delim(" ")
s_string("Oct")
s_delim(" ")
s_string("2012")
s_delim(" ")
s_string("08")
s_delim(":")
s_string("12")
s_delim(":")
s_string("31")
s_delim(" ")
s_string("EST")
s_static("\r\n\r\n")


# Fuzz KeepAlive header
# Keep-Alive: 300
s_initialize("HTTP HEADER KEEPALIVE")
s_static("GET / HTTP/1.1\r\n")
s_static("Keep-Alive")
s_delim(":")
s_delim(" ")
s_string("300")
s_static("\r\n\r\n")


# Fuzz Max-Fowards header
# Max-Forwards: 80
s_initialize("HTTP HEADER MAXFORWARDS")
s_static("GET / HTTP/1.1\r\n")
s_static("Max-Forwards")
s_delim(":")
s_delim(" ")
s_string("80")
s_static("\r\n\r\n")


# Fuzz Pragma header
# Pragma: no-cache
s_initialize("HTTP HEADER PRAGMA")
s_static("GET / HTTP/1.1\r\n")
s_static("Pragma")
s_delim(":")
s_delim(" ")
s_string("no-cache")
s_static("\r\n\r\n")


# Fuzz Proxy-Authorization header
# Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
s_initialize("HTTP HEADER PROXYAUTHORIZATION")
s_static("GET / HTTP/1.1\r\n")
s_static("Proxy-Authorization")
s_delim(":")
s_delim(" ")
s_string("Basic")
s_delim(" ")
s_string("QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
s_static("\r\n\r\n")


# Fuzz Range header
# Range: bytes=500-999
s_initialize("HTTP HEADER RANGE")
s_static("GET / HTTP/1.1\r\n")
s_static("Range")
s_delim(":")
s_delim(" ")
s_string("bytes")
s_delim("=")
s_string("500")
s_delim("-")
s_string("999")
s_static("\r\n\r\n")


# Fuzz Referer header
# Referer: http://www.google.com
s_initialize("HTTP HEADER REFERER")
s_static("GET / HTTP/1.1\r\n")
s_static("Referer")
s_delim(":")
s_delim(" ")
s_string("http://www.google.com")
s_static("\r\n\r\n")


# Fuzz TE header
# TE: trailers, deflate
s_initialize("HTTP HEADER TE")
s_static("GET / HTTP/1.1\r\n")
s_static("TE")
s_delim(":")
s_delim(" ")
s_string("trailers")
s_delim(",")
s_delim(" ")
s_string("deflate")
s_static("\r\n\r\n")


# Fuzz Upgrade header
# Upgrade: HTTP/2.0, SHTTP/1.3, IRC/6.9, RTA/x11
s_initialize("HTTP HEADER UPGRADE")
s_static("GET / HTTP/1.1\r\n")
s_static("Upgrade")
s_delim(":")
s_delim(" ")
s_string("HTTP")
s_delim("/")
s_string("2")
s_delim(".")
s_string("0")
s_delim(",")
s_delim(" ")
s_string("SHTTP")
s_delim("/")
s_string("1")
s_delim(".")
s_string("3")
s_delim(",")
s_delim(" ")
s_string("IRC")
s_delim("/")
s_string("6")
s_delim(".")
s_string("9")
s_delim(",")
s_delim(" ")
s_string("RTA")
s_delim("/")
s_string("x11")
s_static("\r\n\r\n")


# Fuzz User Agent header
# User-Agent: Mozilla/5.0 (Windows; U)
s_initialize("HTTP HEADER USERAGENT")
s_static("GET / HTTP/1.1\r\n")
s_static("User-Agent")
s_delim(":")
s_delim(" ")
s_string("Mozilla/5.0 (Windows; U)")
s_static("\r\n\r\n")


# Fuzz Via header
# Via: 1.0 derp, 1.1 derp.com (Apache/1.1)
s_initialize("HTTP HEADER VIA")
s_static("GET / HTTP/1.1\r\n")
s_static("Via")
s_delim(":")
s_delim(" ")
s_string("1")
s_delim(".")
s_string("0")
s_delim(" ")
s_string("derp")
s_delim(",")
s_delim(" ")
s_string("1")
s_delim(".")
s_string("1")
s_delim(" ")
s_string("derp.com")
s_delim(" ")
s_delim("(")
s_string("Apache")
s_delim("/")
s_string("1")
s_delim(".")
s_string("1")
s_delim(")")
s_static("\r\n\r\n")


# Fuzz Warning header
# Warning: 4141 Sulley Rocks!
s_initialize("HTTP HEADER WARNING")
s_static("GET / HTTP/1.1\r\n")
s_static("Warning")
s_delim(":")
s_delim(" ")
s_string("4141")
s_delim(" ")
s_string("Sulley Rocks!")
s_static("\r\n\r\n")


# Fuzz X-att-deviceid header
# x-att-deviceid: DerpPhone/Rev2309
s_initialize("HTTP HEADER XATTDEVICEID")
s_static("GET / HTTP/1.1\r\n")
s_static("x-att-deviceid")
s_delim(":")
s_delim(" ")
s_string("DerpPhone")
s_delim("/")
s_string("Rev2309")
s_static("\r\n\r\n")


# Fuzz X-Do-Not-Track header
# X-Do-Not-Track: 1
s_initialize("HTTP HEADER XDONOTTRACK")
s_static("GET / HTTP/1.1\r\n")
s_static("X-Do-Not-Track")
s_delim(":")
s_delim(" ")
s_string("1")
s_static("\r\n\r\n")


# Fuzz X-Forwarded-For header
# X-Forwarded-For: client1, proxy1, proxy2
s_initialize("HTTP HEADER XFORWARDEDFOR")
s_static("GET / HTTP/1.1\r\n")
s_static("X-Forwarded-For")
s_delim(":")
s_delim(" ")
s_string("client1")
s_delim(",")
s_delim(" ")
s_string("proxy2")
s_static("\r\n\r\n")


# Fuzz X-Requested-With header
# X-Requested-With: XMLHttpRequest
s_initialize("HTTP HEADER XREQUESTEDWITH")
s_static("GET / HTTP/1.1\r\n")
s_static("X-Requested-With")
s_delim(":")
s_delim(" ")
s_string("XMLHttpRequest")
s_static("\r\n\r\n")


# Fuzz X-WAP-Profile header
# x-wap-profile: http://wap.samsungmobile.com/uaprof/SGH-I777.xml
s_initialize("HTTP HEADER XWAPPROFILE")
s_static("GET / HTTP/1.1\r\n")
s_static("x-wap-profile")
s_delim(":")
s_delim(" ")
s_string("http")
s_delim(":")
s_delim("/")
s_delim("/")
s_string("wap.samsungmobile.com/uaprof/SGH-I777")
s_static(".xml")
s_static("\r\n\r\n")