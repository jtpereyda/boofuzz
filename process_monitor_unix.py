import os
import sys
import getopt
import signal
import time
import threading

from sulley import pedrpc

'''
By nnp
http://www.unprotectedhex.com

This intended as a basic replacement for Sulley's process_monitor.py on *nix.
The below options are accepted. Crash details are limited to the signal that
caused the death and whatever operating system supported mechanism is in place (i.e
core dumps)

Replicated methods:
    - alive
    - log
    - post_send
    - pre_send
    _ start_target
    - stop_target
    - set_start_commands
    - set_stop_commands

Limitations
    - Cannot attach to an already running process
    - Currently only accepts one start_command
    - Limited 'crash binning'. Relies on the availability of core dumps. These
      should be created in the same directory the process is ran from on Linux
      and in the (hidden) /cores directory on OS X. On OS X you have to add 
      the option COREDUMPS=-YES- to /etc/hostconfig and then `ulimit -c
      unlimited` as far as I know. A restart may be required. The file
      specified by crash_bin will any other available details such as the test
      that caused the crash and the signal received by the program
'''

USAGE = "USAGE: process_monitor_unix.py"\
        "\n    -c|--crash_bin             File to record crash info too" \
        "\n    [-P|--port PORT]             TCP port to bind this agent too"\
        "\n    [-l|--log_level LEVEL]       log level (default 1), increase for more verbosity"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)


class debugger_thread:
    def __init__(self, start_command):
        '''
        This class isn't actually ran as a thread, only the start_monitoring
        method is. It can spawn/stop a process, wait for it to exit and report on
        the exit status/code.
        '''
        
        self.start_command = start_command
        self.tokens = start_command.split(' ')
        self.cmd_args = []
        self.pid = None
        self.exit_status = None
        self.alive = False

    def spawn_target(self):
        print self.tokens
        self.pid = os.spawnv(os.P_NOWAIT, self.tokens[0], self.tokens)
        self.alive = True
        
    def start_monitoring(self):
        '''
        self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        while self.exit_status == (0, 0):                    
            self.exit_status = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
        '''
        
        self.exit_status = os.waitpid(self.pid, 0)
        # [0] is the pid
        self.exit_status = self.exit_status[1]
            
        self.alive = False

    def get_exit_status(self):
        return self.exit_status

    def stop_target(self):
        os.kill(self.pid, signal.SIGKILL)
        self.alive = False

    def isAlive(self):
        return self.alive

########################################################################################################################

class nix_process_monitor_pedrpc_server(pedrpc.server):
    def __init__(self, host, port, crash_bin, log_level=1):
        '''
        @type host: String
        @param host: Hostname or IP address
        @type port: Integer
        @param port: Port to bind server to
        @type crash_bin: String
        @param crash_bin: Where to save monitored process crashes for analysis
        
        '''
        
        pedrpc.server.__init__(self, host, port)
        self.crash_bin = crash_bin
        self.log_level = log_level
        self.dbg = None
        self.log("Process Monitor PED-RPC server initialized:")
        self.log("Listening on %s:%s" % (host, port))
        self.log("awaiting requests...")

    def alive (self):
        '''
        Returns True. Useful for PED-RPC clients who want to see if the PED-RPC connection is still alive.
        '''

        return True

    def log (self, msg="", level=1):
        '''
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)

    def post_send (self):
        '''
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        @rtype:  Boolean
        @return: Return True if the target is still active, False otherwise.
        '''

        if not self.dbg.isAlive():
            exit_status = self.dbg.get_exit_status()
            rec_file = open(self.crash_bin, 'a')
            if os.WCOREDUMP(exit_status):
                reason = 'Segmentation fault'
            elif os.WIFSTOPPED(exit_status):
                reason = 'Stopped with signal ' + str(os.WTERMSIG(exit_status))
            elif os.WIFSIGNALED(exit_status):
                reason = 'Terminated with signal ' + str(os.WTERMSIG(exit_status))
            elif os.WIFEXITED(exit_status):
                reason = 'Exit with code - ' + str(os.WEXITSTATUS(exit_status))
            else:
                reason = 'Process died for unknown reason'
                
            self.last_synopsis = '[%s] Crash : Test - %d Reason - %s\n' % (time.strftime("%I:%M.%S"), self.test_number, reason)
            rec_file.write(self.last_synopsis)
            rec_file.close()

        return self.dbg.isAlive()

    def pre_send (self, test_number):
        '''
        This routine is called before the fuzzer transmits a test case and ensure the debugger thread is operational.
        (In this implementation do nothing for now)

        @type  test_number: Integer
        @param test_number: Test number to retrieve PCAP for.
        '''
        if self.dbg == None:
            self.start_target()
            
        self.log("pre_send(%d)" % test_number, 10)
        self.test_number = test_number

    def start_target (self):
        '''
        Start up the target process by issuing the commands in self.start_commands.
        '''

        self.log("starting target process")
        
        self.dbg = debugger_thread(self.start_commands[0])
        self.dbg.spawn_target()
        # prevent blocking by spawning off another thread to waitpid
        threading.Thread(target=self.dbg.start_monitoring).start()
        self.log("done. target up and running, giving it 5 seconds to settle in.")
        time.sleep(5)

    def stop_target (self):
        '''
        Kill the current debugger thread and stop the target process by issuing the commands in self.stop_commands.
        '''

        # give the debugger thread a chance to exit.
        time.sleep(1)

        self.log("stopping target process")

        for command in self.stop_commands:
            if command == "TERMINATE_PID":
                self.dbg.stop_target()
            else:
                os.system(command)

    def set_start_commands (self, start_commands):
        '''
        We expect start_commands to be a list with one element for example
        ['/usr/bin/program arg1 arg2 arg3']
        '''

        if len(start_commands) > 1:
            self.log("This process monitor does not accept > 1 start command")
            return

        self.log("updating start commands to: %s" % start_commands)
        self.start_commands = start_commands


    def set_stop_commands (self, stop_commands):
        self.log("updating stop commands to: %s" % stop_commands)

        self.stop_commands = stop_commands

    def set_proc_name (self, proc_name):
        self.log("updating target process name to '%s'" % proc_name)

        self.proc_name = proc_name

    def get_crash_synopsis (self):
        '''
        Return the last recorded crash synopsis.

        @rtype:  String
        @return: Synopsis of last recorded crash.
        '''

        return self.last_synopsis
    
########################################################################################################################

if __name__ == "__main__":
    # parse command line options.
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:P:l:", ["crash_bin=","port=","log_level=",])
    except getopt.GetoptError:
        ERR(USAGE)

    log_level = 1
    PORT = None
    crash_bin = None
    for opt, arg in opts:
        if opt in ("-c", "--crash_bin"):   crash_bin  = arg
        if opt in ("-P", "--port"): PORT = int(arg)
        if opt in ("-l", "--log_level"):   log_level  = int(arg)

    if not crash_bin: ERR(USAGE)
    
    if PORT == None:
        PORT = 26002
    
    # spawn the PED-RPC servlet.

    servlet = nix_process_monitor_pedrpc_server("0.0.0.0", PORT, crash_bin, log_level)
    servlet.serve_forever()

