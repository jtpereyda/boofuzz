#!/usr/bin/python
#!c:\\python\\python.exe

import os
import sys
import time
import getopt

try:
    from win32api import GetShortPathName
    from win32com.shell import shell
except:
    if os.name == "nt":
        print "[!] Failed to import win32api/win32com modules, please install these! Bailing..."
        sys.exit(1)


from sulley import pedrpc

PORT  = 26003
ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)
USAGE = "USAGE: vmcontrol.py"                                                             \
        "\n    <-x|--vmx FILENAME|NAME> path to VMX to control or name of VirtualBox image" \
        "\n    <-r|--vmrun FILENAME>    path to vmrun.exe or VBoxManage"                    \
        "\n    [-s|--snapshot NAME>     set the snapshot name"                              \
        "\n    [-l|--log_level LEVEL]   log level (default 1), increase for more verbosity" \
        "\n    [-i|--interactive]       Interactive mode, prompts for input values"         \
        "\n    [--port PORT]            TCP port to bind this agent to"                      \
        "\n    [--vbox]                 control an Oracle VirtualBox VM"

########################################################################################################################
class vmcontrol_pedrpc_server (pedrpc.server):
    def __init__ (self, host, port, vmrun, vmx, snap_name=None, log_level=1, interactive=False):
        '''
        @type  host:         String
        @param host:         Hostname or IP address to bind server to
        @type  port:         Integer
        @param port:         Port to bind server to
        @type  vmrun:        String
        @param vmrun:        Path to VMWare vmrun.exe
        @type  vmx:          String
        @param vmx:          Path to VMX file
        @type  snap_name:    String
        @param snap_name:    (Optional, def=None) Snapshot name to revert to on restart
        @type  log_level:    Integer
        @param log_level:    (Optional, def=1) Log output level, increase for more verbosity
        @type  interactive:  Boolean
        @param interactive:  (Option, def=False) Interactive mode, prompts for input values
        '''

        # initialize the PED-RPC server.
        pedrpc.server.__init__(self, host, port)

        self.host        = host
        self.port        = port

        self.interactive = interactive

        if interactive:
            print "[*] Entering interactive mode..."

            # get vmrun path
            try:
                while 1:
                    print "[*] Please browse to the folder containing vmrun.exe..."
                    pidl, disp, imglist = shell.SHBrowseForFolder(0, None, "Please browse to the folder containing vmrun.exe:")
                    fullpath = shell.SHGetPathFromIDList(pidl)
                    file_list = os.listdir(fullpath)
                    if "vmrun.exe" not in file_list:
                        print "[!] vmrun.exe not found in selected folder, please try again"
                    else:
                        vmrun = fullpath + "\\vmrun.exe"
                        print "[*] Using %s" % vmrun
                        break
            except:
                print "[!] Error while trying to find vmrun.exe. Try again without -I."
                sys.exit(1)

            # get vmx path
            try:
                while 1:
                    print "[*] Please browse to the folder containing the .vmx file..."
                    pidl, disp, imglist = shell.SHBrowseForFolder(0, None, "Please browse to the folder containing the .vmx file:")
                    fullpath = shell.SHGetPathFromIDList(pidl)
                    file_list = os.listdir(fullpath)

                    exists = False
                    for file in file_list:
                        idx = file.find(".vmx")
                        if idx == len(file) - 4:
                            exists = True
                            vmx = fullpath + "\\" + file
                            print "[*] Using %s" % vmx

                    if exists:
                        break
                    else:
                        print "[!] No .vmx file found in the selected folder, please try again"
            except:
                raise
                print "[!] Error while trying to find the .vmx file. Try again without -I."
                sys.exit(1)

        # Grab snapshot name and log level if we're in interactive mode
        if interactive:
            snap_name = raw_input("[*] Please enter the snapshot name: ")
            log_level = raw_input("[*] Please enter the log level (default 1): ")

            if log_level:
                log_level = int(log_level)
            else:
                log_level = 1

        # if we're on windows, get the DOS path names
        if os.name == "nt":
            self.vmrun = GetShortPathName(r"%s" % vmrun)
            self.vmx   = GetShortPathName(r"%s" % vmx)
        else:
            self.vmrun = vmrun
            self.vmx   = vmx

        self.snap_name   = snap_name
        self.log_level   = log_level
        self.interactive = interactive

        self.log("VMControl PED-RPC server initialized:")
        self.log("\t vmrun:     %s" % self.vmrun)
        self.log("\t vmx:       %s" % self.vmx)
        self.log("\t snap name: %s" % self.snap_name)
        self.log("\t log level: %d" % self.log_level)
        self.log("Awaiting requests...")


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


    def set_vmrun (self, vmrun):
        self.log("setting vmrun to %s" % vmrun, 2)
        self.vmrun = vmrun


    def set_vmx (self, vmx):
        self.log("setting vmx to %s" % vmx, 2)
        self.vmx = vmx


    def set_snap_name (self, snap_name):
        self.log("setting snap_name to %s" % snap_name, 2)
        self.snap_name = snap_name


    def vmcommand (self, command):
        '''
        Execute the specified command, keep trying in the event of a failure.

        @type  command: String
        @param command: VMRun command to execute
        '''

        while 1:
            self.log("executing: %s" % command, 5)

            pipe = os.popen(command)
            out  = pipe.readlines()

            try:
                pipe.close()
            except IOError:
                self.log("IOError trying to close pipe")

            if not out:
                break
            elif not out[0].lower().startswith("close failed"):
                break

            self.log("failed executing command '%s' (%s). will try again." % (command, out))
            time.sleep(1)

        return "".join(out)


    ###
    ### VMRUN COMMAND WRAPPERS
    ###


    def delete_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("deleting snapshot: %s" % snap_name, 2)

        command = self.vmrun + " deleteSnapshot " + self.vmx + " " + '"' + snap_name + '"'
        return self.vmcommand(command)


    def list (self):
        self.log("listing running images", 2)

        command = self.vmrun + " list"
        return self.vmcommand(command)


    def list_snapshots (self):
        self.log("listing snapshots", 2)

        command = self.vmrun + " listSnapshots " + self.vmx
        return self.vmcommand(command)


    def reset (self):
        self.log("resetting image", 2)

        command = self.vmrun + " reset " + self.vmx
        return self.vmcommand(command)


    def revert_to_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("reverting to snapshot: %s" % snap_name, 2)

        command = self.vmrun + " revertToSnapshot " + self.vmx + " " + '"' + snap_name + '"'
        return self.vmcommand(command)


    def snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("taking snapshot: %s" % snap_name, 2)

        command = self.vmrun + " snapshot " + self.vmx + " " + '"' + snap_name + '"'

        return self.vmcommand(command)


    def start (self):
        self.log("starting image", 2)

        command = self.vmrun + " start " + self.vmx
        return self.vmcommand(command)


    def stop (self):
        self.log("stopping image", 2)

        command = self.vmrun + " stop " + self.vmx
        return self.vmcommand(command)


    def suspend (self):
        self.log("suspending image", 2)

        command = self.vmrun + " suspend " + self.vmx
        return self.vmcommand(command)


    ###
    ### EXTENDED COMMANDS
    ###


    def restart_target (self):
        self.log("restarting virtual machine...")

        # revert to the specified snapshot and start the image.
        self.revert_to_snapshot()
        self.start()

        # wait for the snapshot to come alive.
        self.wait()


    def is_target_running (self):
        # sometimes vmrun reports that the VM is up while it's still reverting.
        time.sleep(10)

        for line in self.list().lower().split('\n'):
            if os.name == "nt":
                try:
                    line = GetShortPathName(line)
                # skip invalid paths.
                except:
                    continue

            if self.vmx.lower() == line.lower():
                return True

        return False


    def wait (self):
        self.log("waiting for vmx to come up: %s" % self.vmx)
        while 1:
            if self.is_target_running():
                break


########################################################################################################################

########################################################################################################################
class vboxcontrol_pedrpc_server (vmcontrol_pedrpc_server):
    def __init__ (self, host, port, vmrun, vmx, snap_name=None, log_level=1, interactive=False):
        '''
        Controls an Oracle VirtualBox Virtual Machine
        
        @type  host:         String
        @param host:         Hostname or IP address to bind server to
        @type  port:         Integer
        @param port:         Port to bind server to
        @type  vmrun:        String
        @param vmrun:        Path to VBoxManage
        @type  vmx:          String
        @param vmx:          Name of the virtualbox VM to control (no quotes)
        @type  snap_name:    String
        @param snap_name:    (Optional, def=None) Snapshot name to revert to on restart
        @type  log_level:    Integer
        @param log_level:    (Optional, def=1) Log output level, increase for more verbosity
        @type  interactive:  Boolean
        @param interactive:  (Option, def=False) Interactive mode, prompts for input values
        '''

        # initialize the PED-RPC server.
        pedrpc.server.__init__(self, host, port)

        self.host        = host
        self.port        = port

        self.interactive = interactive
 

    
        if interactive:
            print "[*] Entering interactive mode..."

            # get vmrun path
            try:
                while 1:
                    print "[*] Please browse to the folder containing VBoxManage.exe..."
                    pidl, disp, imglist = shell.SHBrowseForFolder(0, None, "Please browse to the folder containing VBoxManage.exe")
                    fullpath = shell.SHGetPathFromIDList(pidl)
                    file_list = os.listdir(fullpath)
                    if "VBoxManage.exe" not in file_list:
                        print "[!] VBoxManage.exe not found in selected folder, please try again"
                    else:
                        vmrun = fullpath + "\\VBoxManage.exe"
                        print "[*] Using %s" % vmrun
                        break
            except:
                print "[!] Error while trying to find VBoxManage.exe. Try again without -I."
                sys.exit(1)



        # Grab vmx, snapshot name and log level if we're in interactive mode

        if interactive:
            vmx = raw_input("[*] Please enter the VirtualBox virtual machine name: ")
            snap_name = raw_input("[*] Please enter the snapshot name: ")
            log_level = raw_input("[*] Please enter the log level (default 1): ")
    

        if log_level:
            log_level = int(log_level)
        else:
            log_level = 1


        # if we're on windows, get the DOS path names

        if os.name == "nt":
            self.vmrun = GetShortPathName(r"%s" % vmrun)
            self.vmx   = GetShortPathName(r"%s" % vmx)
        else:
    
            self.vmrun = vmrun
            self.vmx   = vmx

        self.snap_name   = snap_name
        self.log_level   = log_level
        self.interactive = interactive

        self.log("VirtualBox PED-RPC server initialized:")
        self.log("\t vboxmanage:     %s" % self.vmrun)
        self.log("\t machine name:       %s" % self.vmx)
        self.log("\t snap name: %s" % self.snap_name)
        self.log("\t log level: %d" % self.log_level)
        self.log("Awaiting requests...")

    ###
    ### VBOXMANAGE COMMAND WRAPPERS
    ###


    def delete_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        self.log("deleting snapshot: %s" % snap_name, 2)

        command = self.vmrun + " snapshot " + self.vmx + " delete " + snap_name + '"'
        return self.vmcommand(command)


    def list (self):
        self.log("listing running images", 2)

        command = self.vmrun + " list runningvms"
        return self.vmcommand(command)


    def list_snapshots (self):
        self.log("listing snapshots", 2)

        command = self.vmrun + " snapshot " + self.vmx + " list"
        return self.vmcommand(command)


    def reset (self):
        self.log("resetting image", 2)

        command = self.vmrun + " controlvm " + self.vmx + " reset"
        return self.vmcommand(command)

    def pause (self):
        self.log("pausing image", 2)

        command = self.vmrun + " controlvm " + self.vmx + " pause"
        return self.vmcommand(command)
    
    def resume (self):
        self.log("resuming image", 2)

        command = self.vmrun + " controlvm " + self.vmx + " resume"
        return self.vmcommand(command)

    def revert_to_snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        #VirtualBox flips out if you try to do this with a running VM
        if self.is_target_running():
            self.stop()



        self.log("reverting to snapshot: %s" % snap_name, 2)

        command = self.vmrun + " snapshot " + self.vmx + " restore " + snap_name 
        return self.vmcommand(command)


    def snapshot (self, snap_name=None):
        if not snap_name:
            snap_name = self.snap_name

        #VirtualBox flips out if you try to do this with a running VM
        if self.is_target_running():
               self.pause()


        self.log("taking snapshot: %s" % snap_name, 2)

        command = self.vmrun + " snapshot " + self.vmx + " take " + snap_name

        return self.vmcommand(command)


    def start (self):
        self.log("starting image", 2)

        command = self.vmrun + " startvm " + self.vmx 
        # TODO: we may want to do more here with headless, gui, etc...
        return self.vmcommand(command)


    def stop (self):
        self.log("stopping image", 2)

        command = self.vmrun + " controlvm " + self.vmx + " poweroff"
        return self.vmcommand(command)


    def suspend (self):
        self.log("suspending image", 2)

        command = self.vmrun + " controlvm " + self.vmx + " pause"
        return self.vmcommand(command)


    ###
    ### EXTENDED COMMANDS
    ###

#added a function here to get vminfo... useful for parsing stuff out later
    def get_vminfo(self):

           self.log("getting vminfo", 2)

           command = self.vmrun + " showvminfo " + self.vmx + " --machinereadable"
           return self.vmcommand(command)


    def restart_target (self):
        self.log("restarting virtual machine...")
    
        #VirtualBox flips out if you try to do this with a running VM
        if self.is_target_running():
            self.stop()

        # revert to the specified snapshot and start the image.
        self.revert_to_snapshot()
        self.start()

        # wait for the snapshot to come alive.
        self.wait()


    def is_target_running (self):
        # sometimes vmrun reports that the VM is up while it's still reverting.
        time.sleep(10)

        for line in self.get_vminfo().split('\n'):
            if line == 'VMState="running"':
                return True

        return False
    
    def is_target_paused (self):
        time.sleep(10)
        
        for line in self.get_vminfo().split('\n'):
            if line == 'VMState="paused"':
                return True

        return False


########################################################################################################################

if __name__ == "__main__":
    # parse command line options.
    try:
        opts, args = getopt.getopt(sys.argv[1:], "x:r:s:l:i", ["vmx=", "vmrun=", "snapshot=", "log_level=", "interactive", "port=", "vbox"])
    except getopt.GetoptError:
        ERR(USAGE)

    vmrun       = r"C:\progra~1\vmware\vmware~1\vmrun.exe"
    vmx         = None
    snap_name   = None
    log_level   = 1
    interactive = False
    virtualbox  = False
    
    for opt, arg in opts:
        if opt in ("-x", "--vmx"):         vmx         = arg
        if opt in ("-r", "--vmrun"):       vmrun       = arg
        if opt in ("-s", "--snapshot"):    snap_name   = arg
        if opt in ("-l", "--log_level"):   log_level   = int(arg)
        if opt in ("-i", "--interactive"): interactive = True
        if opt in ("--port"):              PORT        = int(arg)
        if opt in ("--vbox"):              virtualbox  = True
        
    # OS check
    if interactive and not os.name == "nt":
        print "[!] Interactive mode currently only works on Windows operating systems."
        ERR(USAGE)

    if not vmx and not interactive:
        ERR(USAGE)
    
    if not virtualbox:
        servlet = vmcontrol_pedrpc_server("0.0.0.0", PORT, vmrun, vmx, snap_name, log_level, interactive)
    elif virtualbox:
        servlet = vboxcontrol_pedrpc_server("0.0.0.0", PORT, vmrun, vmx, snap_name, log_level, interactive)
    
    servlet.serve_forever()
