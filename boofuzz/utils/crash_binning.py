#
# Crash Binning
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: crash_binning.py 193 2007-04-05 13:30:01Z cameron $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
"""

import zlib
import cPickle


class CrashBinStruct:
    def __init__(self):
        self.exception_module    = None
        self.exception_address   = 0
        self.write_violation     = 0
        self.violation_address   = 0
        self.violation_thread_id = 0
        self.context             = None
        self.context_dump        = None
        self.disasm              = None
        self.disasm_around       = []
        self.stack_unwind        = []
        self.seh_unwind          = []
        self.extra               = None


class CrashBinning:
    """
    @todo: Add MySQL import/export.
    """

    bins       = {}
    last_crash = None
    pydbg      = None

    def __init__(self):
        self.bins       = {}
        self.last_crash = None
        self.pydbg      = None

    def record_crash(self, pydbg, extra=None):
        """
        Given a PyDbg instantiation that at the current time is assumed to have "crashed" (access violation for example)
        record various details such as the disassemly around the violating address, the ID of the offending thread, the
        call stack and the SEH unwind. Store the recorded data in an internal dictionary, binning them by the exception
        address.

        @type  pydbg: pydbg
        @param pydbg: Instance of pydbg
        @type  extra: Mixed
        @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin
        """

        self.pydbg = pydbg
        crash = CrashBinStruct()

        # add module name to the exception address.
        exception_module = pydbg.addr_to_module(pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress)

        if exception_module:
            exception_module = exception_module.szModule
        else:
            exception_module = "[INVALID]"

        crash.exception_module    = exception_module
        crash.exception_address   = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress
        crash.write_violation     = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        crash.violation_address   = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
        crash.violation_thread_id = pydbg.dbg.dwThreadId
        crash.context             = pydbg.context
        crash.context_dump        = pydbg.dump_context(pydbg.context, print_dots=False)
        crash.disasm              = pydbg.disasm(crash.exception_address)
        crash.disasm_around       = pydbg.disasm_around(crash.exception_address, 10)
        crash.stack_unwind        = pydbg.stack_unwind()
        crash.seh_unwind          = pydbg.seh_unwind()
        crash.extra               = extra

        # add module names to the stack unwind.
        for i in xrange(len(crash.stack_unwind)):
            addr   = crash.stack_unwind[i]
            module = pydbg.addr_to_module(addr)

            if module:
                module = module.szModule
            else:
                module = "[INVALID]"

            crash.stack_unwind[i] = "%s:%08x" % (module, addr)

        # add module names to the SEH unwind.
        for i in xrange(len(crash.seh_unwind)):
            (addr, handler) = crash.seh_unwind[i]

            module = pydbg.addr_to_module(handler)

            if module:
                module = module.szModule
            else:
                module = "[INVALID]"

            crash.seh_unwind[i] = (addr, handler, "%s:%08x" % (module, handler))

        if not crash.exception_address in self.bins:
            self.bins[crash.exception_address] = []

        self.bins[crash.exception_address].append(crash)
        self.last_crash = crash

    def crash_synopsis(self, crash=None):
        """
        For the supplied crash, generate and return a report containing the disassemly around the violating address,
        the ID of the offending thread, the call stack and the SEH unwind. If not crash is specified, then call through
        to last_crash_synopsis() which returns the same information for the last recorded crash.

        @see: crash_synopsis()

        @type  crash: CrashBinStruct
        @param crash: (Optional, def=None) Crash object to generate report on

        @rtype:  str
        @return: Crash report
        """

        if not crash:
            return self.last_crash_synopsis()

        if crash.write_violation:
            direction = "write to"
        else:
            direction = "read from"

        synopsis = "%s:%08x %s from thread %d caused access violation\nwhen attempting to %s 0x%08x\n\n" % \
            (
                crash.exception_module,
                crash.exception_address,
                crash.disasm,
                crash.violation_thread_id,
                direction,
                crash.violation_address
            )

        synopsis += crash.context_dump

        synopsis += "\ndisasm around:\n"
        for (ea, inst) in crash.disasm_around:
            synopsis += "\t0x%08x %s\n" % (ea, inst)

        if len(crash.stack_unwind):
            synopsis += "\nstack unwind:\n"
            for entry in crash.stack_unwind:
                synopsis += "\t%s\n" % entry

        if len(crash.seh_unwind):
            synopsis += "\nSEH unwind:\n"
            for (addr, handler, handler_str) in crash.seh_unwind:
                synopsis += "\t%08x -> %s\n" % (addr, handler_str)

        return synopsis + "\n"

    def export_file(self, file_name):
        """
        Dump the entire object structure to disk.

        @see: import_file()

        @type  file_name:   str
        @param file_name:   File name to export to

        @rtype:             CrashBinning
        @return:            self
        """

        # null out what we don't serialize but save copies to restore after dumping to disk.
        last_crash = self.last_crash
        pydbg      = self.pydbg

        self.last_crash = self.pydbg = None

        fh = open(file_name, "wb+")
        fh.write(zlib.compress(cPickle.dumps(self, protocol=2)))
        fh.close()

        self.last_crash = last_crash
        self.pydbg      = pydbg

        return self

    def import_file(self, file_name):
        """
        Load the entire object structure from disk.

        @see: export_file()

        @type  file_name:   str
        @param file_name:   File name to import from

        @rtype:             CrashBinning
        @return:            self
        """

        fh  = open(file_name, "rb")
        tmp = cPickle.loads(zlib.decompress(fh.read()))
        fh.close()

        self.bins = tmp.bins

        return self

    def last_crash_synopsis(self):
        """
        For the last recorded crash, generate and return a report containing the disassemly around the violating
        address, the ID of the offending thread, the call stack and the SEH unwind.

        @see: crash_synopsis()

        @rtype:  String
        @return: Crash report
        """

        if self.last_crash.write_violation:
            direction = "write to"
        else:
            direction = "read from"

        synopsis = "%s:%08x %s from thread %d caused access violation\nwhen attempting to %s 0x%08x\n\n" % \
            (
                self.last_crash.exception_module,
                self.last_crash.exception_address,
                self.last_crash.disasm,
                self.last_crash.violation_thread_id,
                direction,
                self.last_crash.violation_address
            )

        synopsis += self.last_crash.context_dump

        synopsis += "\ndisasm around:\n"
        for (ea, inst) in self.last_crash.disasm_around:
            synopsis += "\t0x%08x %s\n" % (ea, inst)

        if len(self.last_crash.stack_unwind):
            synopsis += "\nstack unwind:\n"
            for entry in self.last_crash.stack_unwind:
                synopsis += "\t%s\n" % entry

        if len(self.last_crash.seh_unwind):
            synopsis += "\nSEH unwind:\n"
            for (addr, handler, handler_str) in self.last_crash.seh_unwind:
                try:
                    disasm = self.pydbg.disasm(handler)
                except Exception:
                    disasm = "[INVALID]"

                synopsis += "\t%08x -> %s %s\n" % (addr, handler_str, disasm)

        return synopsis + "\n"