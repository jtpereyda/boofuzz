from boofuzz import *


s_initialize("chat init")

"""
<?xml version="1.0" encoding="UTF-8" ?>
<stream:stream to="192.168.200.17" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams">
"""

# i'll fuzz these bitches later.
# TODO: still need to figure out how to incorporate dynamic IPs
s_static('<?xml version="1.0" encoding="UTF-8" ?>')
s_static('<stream:stream to="152.67.137.126" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams">')

s_initialize("chat message")
s_static('<message to="TSR@GIZMO" type="chat">\n')
s_static('<body></body>\n')
s_static('<html xmlns="http://www.w3.org/1999/xhtml"><body></body></html><x xmlns="jabber:x:event">\n')
s_static('<composing/>\n')
s_static('<id></id>\n')
s_static('</x>\n')
s_static('</message>\n')

# s_static('<message to="TSR@GIZMO" type="chat">\n')
s_delim("<")
s_string("message")
s_delim(" ")
s_string("to")
s_delim("=")
s_delim('"')
s_string("TSR@GIZMO")
s_delim('"')
s_static(' type="chat"')
s_delim(">")
s_delim("\n")

# s_static('<body>hello from python!</body>\n')
s_static("<body>")
s_string("hello from python!")
s_static("</body>\n")

# s_static('
#      <html xmlns="http://www.w3.org/1999/xhtml">
#        <body>
#          <font face="Helvetica" ABSZ="12" color="#000000">hello from python</font>
#        </body>
#      </html>
#      <x xmlns="jabber:x:event">\n
# ')
s_static('<html xmlns="http://www.w3.org/1999/xhtml"><body>')
s_static("<")
s_string("font")
s_static(' face="')
s_string("Helvetica")
s_string('" ABSZ="')
s_word(12, output_format="ascii", signed=True)
s_static('" color="')
s_string("#000000")
s_static('">')
s_string("hello from python")
s_static('</font></body></html><x xmlns="jabber:x:event">\n')

s_static('<composing/>\n')
s_static('</x>\n')
s_static('</message>\n')
