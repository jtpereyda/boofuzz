"""
mediaconnect port 2869
"""

from sulley import *

########################################################################################################################
s_initialize("mediaconnect: get album list")

# POST /upnphost/udhisapi.dll?control=uuid:848a20cc-91bc-4a02-8180-187baa537527+urn:microsoft-com:serviceId:MSContentDirectory HTTP/1.1
s_group("verbs", values=["GET", "POST"])
s_delim(" ")
s_delim("/")
s_string("upnphost/udhisapi.dll")
s_delim("?")
s_string("control")
s_delim("=")
s_string("uuid")
s_delim(":")
s_string("848a20cc-91bc-4a02-8180-187baa537527")
s_delim("+")
s_static("urn")
s_delim(":")
s_string("microsoft-com:serviceId:MSContentDirectory")
s_static(" HTTP/1.1\r\n")

# User-Agent: Xbox/2.0.4552.0 UPnP/1.0 Xbox/2.0.4552.0
# we take this opportunity to fuzz headers in general.
s_string("User-Agent")
s_delim(":")
s_delim(" ")
s_string("Xbox")
s_delim("/")
s_string("2.0.4552.0 UPnP/1.0 Xbox/2.0.4552.0")
s_static("\r\n")

# Connection: Keep-alive
s_static("Connection: ")
s_string("Keep-alive")
s_static("\r\n")

# Host:10.10.20.111
s_static("Host: 10.10.20.111")
s_static("\r\n")

# SOAPACTION: "urn:schemas-microsoft-com:service:MSContentDirectory:1#Search"
s_static("SOAPACTION: ")
s_delim("\"")
s_static("urn")
s_delim(":")
s_string("schemas-microsoft-com")
s_static(":")
s_string("service")
s_static(":")
s_string("MSContentDirectory")
s_static(":")
s_string("1")
s_delim("#")
s_string("Search")
s_delim("\"")
s_static("\r\n")

# CONTENT-TYPE: text/xml; charset="utf-8"
s_static("CONTENT-TYPE: text/xml; charset=\"utf-8\"")
s_static("\r\n")

# Content-Length: 547
s_static("Content-Length: ")
s_sizer("content", format="ascii", signed=True, fuzzable=True)
s_static("\r\n\r\n")

if s_block_start("content"):
    # <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    s_delim("<")
    s_string("s")
    s_delim(":")
    s_string("Envelope")
    s_static(" xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ")
    s_static("s:")
    s_string("encodingStyle")
    s_delim("=")
    s_string("\"http://schemas.xmlsoap.org/soap/encoding/\"")
    s_delim(">")

    s_static("<s:Body>")
    s_static("<u:Search xmlns:u=\"urn:schemas-microsoft-com:service:MSContentDirectory:1\">")

    # <ContainerID>7</ContainerID>
    s_static("<ContainerID>")
    s_dword(7, format="ascii", signed=True)
    s_static("</ContainerID>")

    # <SearchCriteria>(upnp:class = &quot;object.container.album.musicAlbum&quot;)</SearchCriteria>
    s_static("<SearchCriteria>(upnp:class = &quot;")
    s_string("object.container.album.musicAlbum")
    s_static("&quot;)</SearchCriteria>")

    # <Filter>dc:title,upnp:artist</Filter>
    s_static("<Filter>")
    s_delim("dc")
    s_delim(":")
    s_string("title")
    s_delim(",")
    s_string("upnp")
    s_delim(":")
    s_string("artist")
    s_static("</Filter>")

    # <StartingIndex>0</StartingIndex>
    s_static("<StartingIndex>")
    s_dword(0, format="ascii", signed=True)
    s_static("</StartingIndex>")

    # <RequestedCount>1000</RequestedCount>
    s_static("<RequestedCount>")
    s_dword(1000, format="ascii", signed=True)
    s_static("</RequestedCount>")

    s_static("<SortCriteria>+dc:title</SortCriteria>")
    s_static("</u:Search>")
    s_static("</s:Body>")

    # </s:Envelope>
    s_delim("<")
    s_delim("/")
    s_delim("s")
    s_delim(":")
    s_string("Envelope")
    s_delim(">")

s_block_end()