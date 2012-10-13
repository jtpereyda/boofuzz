from sulley import *
########################################################################################################################
# All POST mimetypes that I could think of/find
########################################################################################################################
# List of all blocks defined here (for easy copy/paste)
"""
sess.connect(s_get("HTTP VERBS POST"))
sess.connect(s_get("HTTP VERBS POST ALL"))
sess.connect(s_get("HTTP VERBS POST REQ"))
"""

########################################################################################################################
# Fuzz POST requests with most MIMETypes known
########################################################################################################################
s_initialize("HTTP VERBS POST ALL")
s_static("POST / HTTP/1.1\r\n")
s_static("Content-Type: ")
s_group("mimetypes",values=["audio/basic","audio/x-mpeg","drawing/x-dwf","graphics/x-inventor","image/x-portable-bitmap",
                   "message/external-body","message/http","message/news","message/partial","message/rfc822",
                   "multipart/alternative","multipart/appledouble","multipart/digest","multipart/form-data",
                   "multipart/header-set","multipart/mixed","multipart/parallel","multipart/related","multipart/report",
                   "multipart/voice-message","multipart/x-mixed-replace","text/css","text/enriched","text/html",
                   "text/javascript","text/plain","text/richtext","text/sgml","text/tab-separated-values","text/vbscript",
                   "video/x-msvideo","video/x-sgi-movie","workbook/formulaone","x-conference/x-cooltalk","x-form/x-openscape",
                   "x-music/x-midi","x-script/x-wfxclient","x-world/x-3dmf"])
if s_block_start("mime", group="mimetypes"):
    s_static("\r\n")
    s_static("Content-Length: ")
    s_size("post blob", format="ascii", signed=True, fuzzable=True)
    s_static("\r\n\r\n")
s_block_end()

if s_block_start("post blob"):
    s_string("A"*100 + "=" + "B"*100)
s_block_end()
s_static("\r\n\r\n")

########################################################################################################################
# Basic fuzz of post payloads
########################################################################################################################
s_initialize("HTTP VERBS POST")
s_static("POST / HTTP/1.1\r\n")
s_static("Content-Type: ")
s_string("application/x-www-form-urlencoded")
s_static("\r\n")
s_static("Content-Length: ")
s_size("post blob", format="ascii", signed=True, fuzzable=True)
s_static("\r\n")
if s_block_start("post blob"):
    s_string("A"*100 + "=" + "B"*100)
s_block_end()
s_static("\r\n\r\n")

########################################################################################################################
# Fuzz POST request MIMETypes
########################################################################################################################
s_initialize("HTTP VERBS POST REQ")
s_static("POST / HTTP/1.1\r\n")
s_static("Content-Type: ")
s_string("application")
s_delim("/")
s_string("x")
s_delim("-")
s_string("www")
s_delim("-")
s_string("form")
s_delim("-")
s_string("urlencoded")
s_static("\r\n")
s_static("Content-Length: ")
s_size("post blob", format="ascii", signed=True, fuzzable=True)
s_static("\r\n")
if s_block_start("post blob"):
    s_string("A"*100 + "=" + "B"*100)
s_block_end()
s_static("\r\n\r\n")