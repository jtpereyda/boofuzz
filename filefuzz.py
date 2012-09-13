'''
    Nikolai Rusakov <nikolai.rusakov@gmail.com>

    Example to go along with the extension to sulley for file fuzzing via rpc.
    I have only tested this with small files... larger samples may lead to severe performance degradation
'''
from sulley import sessions, pedrpc
from sulley import *

class file_session(sessions.session):
    def transmit(self, sock, node, edge, target):
        data = None
        # if the edge has a callback, process it. the callback has the option to render the node, modify it and return.
        if edge.callback:
            data = edge.callback(self, node, edge, sock)

        self.logger.error("xmitting: [%d.%d]" % (node.id, self.total_mutant_index))

        # if no data was returned by the callback, render the node here.
        if not data:
            data = node.render()

        #send file data over rpc to procmon
        target.procmon.on_send(self.total_mutant_index, data)

    def restart_target(self, target, stop_first=True):
        pass

    def fuzz(self, this_node=None, path=[]):
        #tcp is default so we disable connecting since we are going to send data over rpc to procmon
        self.connect_befor_send=False
        super(file_session, self).fuzz(this_node, path)

#just using this for the sake of example, pcap header only
s_initialize('pcap')
if s_block_start('pcap'):
    s_dword(0xa1b2c3d4, name='magic', fuzzable=False)
    s_word(2, name='major')
    s_word(4, name='minor')
    s_dword(0, name='thiszone')
    s_dword(0, name='sigfigs')
    s_dword(96, name='snaplen')
    s_dword(1, name='network')
s_block_end()

sess = file_session(session_filename='\\work\\audit\\test', start_webserver=True, sleep_time=0.0) #no need to delay, throttled by procmon
target = sessions.target('localhost', 30000) # doesnt matter transmit is overridden we ship data over rpc
target.procmon = pedrpc.client('localhost', 26002)
target.procmon_options = {
    'proc_path' : '\\progra~1\\wireshark\\tshark-crash.exe', #a modded version of tshark to crash on improper pcap major ver
    'proc_args' : '-r %s', #%s will be replaced with the filepath/name to audit
    'file_path' : 'c:\\work\\audit\\files\\', #where to store the testcase files
    #'finish_bp' : 0x01004a0d, #you may set this to 0 if you wish to rely on max_lifetime/process termination
    'finish_bp' : 0,
    'max_lifetime' : 3.0, #ttl
    'show_window' : False,
}

sess.add_target(target)
sess.connect(sess.root, s_get('pcap'))
sess.fuzz()


