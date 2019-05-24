from boofuzz import *
from boofuzz import utils
import sys, time

test = True

s_initialize("HTTP")

s_group("methods", values=["GET", "HEAD", "POST", "TRACE","PUT","DELETE","CONNECT","OPTIONS","TRACE","PATCH"])
if s_block_start("body", group="methods"):
	s_delim(" ")
	s_delim("/")
	s_string("index.html")
	s_delim(" ")
	s_string("HTTP")
	s_delim("/")
	s_string("1")
	s_delim(".")
	s_string("1")
	s_static("\r\n")
	s_static('Host: 192.168.231.140')
	s_static("\r\n")
s_block_end("body")


s_group("headers", values=["From","Accept","Accept-Encoding","Accept-Language","User-Agent","Referer","Authorization","Charge-To","If-Modified-Since","Pragma","User-Agent","Connection"])
if s_block_start("head", group="headers"):
	s_delim(":")
	s_delim(" ")
	s_string('header-data')
	s_static("\r\n")
s_block_end("head")


if s_block_start("post_datasi", dep="methods", dep_value="POST"):
	s_static('Content-Type: application/x-www-form-urlencoded')
	s_static("\r\n\r\n")
	s_string('param_name1')
	s_delim('=')
	s_string('param_data1')
	s_delim('&')
	s_string('param_name2')
	s_delim('=')
	s_string('param_data2')
s_block_end("post_datasi")

s_static("\r\n\r\n")

s = sessions.Session(session_filename="tiny_port_80.session")


target = sessions.Target(SocketConnection(host="192.168.231.140", port=80))
target.netmon  = pedrpc.Client("127.0.0.1", 26001)
target.procmon = pedrpc.Client("192.168.231.140", 26002)
target.procmon_options =  {
	"proc_name"      : "tiny.exe",
	"stop_commands"  : ['wmic process where (name="tiny.exe") delete'],
	"start_commands" : ['C:\\tinyweb\\tiny.exe C:\\www\\root']
}

s.add_target(target)
print	"Mutations:	"	+	str(s_num_mutations())
##print "Press CTRL/C to cancel in ",
##for i in range(3):
##	print str(3 - i) + " ",
##	sys.stdout.flush()
##	time.sleep(1)
s.connect(s.root, s_get("HTTP"))
while s.fuzz():
	  print s_render()

