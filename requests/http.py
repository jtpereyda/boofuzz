from sulley import *
########################################################################################################################
# Old http.py request primitives, http_* does all of these and many more (AFAIK)
########################################################################################################################
# List of all blocks defined here (for easy copy/paste)
"""
sess.connect(s_get("HTTP VERBS"))
sess.connect(s_get("HTTP VERBS BASIC"))
sess.connect(s_get("HTTP VERBS POST"))
sess.connect(s_get("HTTP HEADERS"))
sess.connect(s_get("HTTP COOKIE"))
"""

s_initialize("HTTP VERBS")
s_group("verbs", values=["GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND"])
if s_block_start("body", group="verbs"):
    s_delim(" ")
    s_delim("/")
    s_string("index.html")
    s_delim(" ")
    s_string("HTTP")
    s_delim("/")
    s_string("1")
    s_delim(".")
    s_string("1")
    s_static("\r\n\r\n")
s_block_end()


########################################################################################################################
s_initialize("HTTP VERBS BASIC")
s_group("verbs", values=["GET", "HEAD"])
if s_block_start("body", group="verbs"):
    s_delim(" ")
    s_delim("/")
    s_string("index.html")
    s_delim(" ")
    s_string("HTTP")
    s_delim("/")
    s_string("1")
    s_delim(".")
    s_string("1")
    s_static("\r\n\r\n")
s_block_end()


########################################################################################################################
s_initialize("HTTP VERBS POST")
s_static("POST / HTTP/1.1\r\n")
s_static("Content-Type: ")
s_string("application/x-www-form-urlencoded")
s_static("\r\n")
s_static("Content-Length: ")
s_size("post blob", format="ascii", signed=True, fuzzable=True)
s_static("\r\n\r\n")

if s_block_start("post blob"):
    s_string("A"*100 + "=" + "B"*100)
s_block_end()


########################################################################################################################
s_initialize("HTTP HEADERS")
s_static("GET / HTTP/1.1\r\n")

# let's fuzz random headers with malformed delimiters.
s_string("Host")
s_delim(":")
s_delim(" ")
s_string("localhost")
s_delim("\r\n")

# let's fuzz the value portion of some popular headers.
s_static("User-Agent: ")
s_string("Mozilla/5.0 (Windows; U)")
s_static("\r\n")

s_static("Accept-Language: ")
s_string("en-us")
s_delim(",")
s_string("en;q=0.5")
s_static("\r\n")

s_static("Keep-Alive: ")
s_string("300")
s_static("\r\n")

s_static("Connection: ")
s_string("keep-alive")
s_static("\r\n")

s_static("Referer: ")
s_string("http://dvlabs.tippingpoint.com")
s_static("\r\n")
s_static("\r\n")


########################################################################################################################
s_initialize("HTTP COOKIE")
s_static("GET / HTTP/1.1\r\n")

if s_block_start("cookie"):
    s_static("Cookie: ")
    s_string("auth")
    s_delim("=")
    s_string("1234567890")
    s_static("\r\n")
    s_block_end()

s_repeat("cookie", max_reps=5000, step=500)
s_static("\r\n")