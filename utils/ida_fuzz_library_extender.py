#!c:\python\python.exe
#
# Aaron Portnoy
# TippingPoint Security Research Team
# (C) 2007
#


def get_string(ea):
    str_type = GetStringType(ea)

    if str_type == 0:
        string_buf = ""
        while Byte(ea) != 0x00:
            string_buf += "%c" % Byte(ea)
            ea += 1
        return string_buf
    elif str_type == 3:
        string_buf = ""
        while Word(ea) != 0x0000:
            string_buf += "%c%c" % (Byte(ea), Byte(ea + 1))
            ea += 2
        return string_buf
    else:
        pass


def get_arguments(ea):
    xref_ea = ea
    args = 0
    found = None

    if GetMnem(xref_ea) != "call":
        return False

    cur_ea = PrevHead(ea, xref_ea - 32)
    while (cur_ea < xref_ea - 32) or (args <= 6):
        cur_mnem = GetMnem(cur_ea)
        if cur_mnem == "push":
            args += 1
            op_type = GetOpType(cur_ea, 0)

            if Comment(cur_ea):
                pass
                # print(" %s = %s," % (Comment(cur_ea), GetOpnd(cur_ea, 0)))
            else:
                if op_type == 1:
                    pass
                    # print(" %s" % GetOpnd(cur_ea, 0))
                elif op_type == 5:
                    found = get_string(GetOperandValue(cur_ea, 0))

        elif cur_mnem == "call" or "j" in cur_mnem:
            break

        cur_ea = PrevHead(cur_ea, xref_ea - 32)

    if found:
        return found


def find_ints(start_address):
    constants = []

    # loop heads
    for head in Heads(start_address, SegEnd(start_address)):

        # if it's code, check for cmp instruction
        if isCode(GetFlags(head)):
            mnem = GetMnem(head)
            op1 = int(GetOperandValue(head, 1))

            # if it's a cmp and it's immediate value is unique, add it to the list
            if "cmp" in mnem and op1 not in constants:
                constants.append(op1)

    print "Found %d constant values used in compares." % len(constants)
    print "-----------------------------------------------------"
    for i in xrange(0, len(constants), 20):
        print constants[i:i + 20]

    return constants


def find_strings(start_address):
    strings = []

    # do import checking
    import_ea = start_address

    while import_ea < SegEnd(start_address):
        import_name = Name(import_ea)

        if len(import_name) > 1 and "cmp" in import_name:
            xref_start = import_ea
            xref_cur = DfirstB(xref_start)
            while xref_cur != BADADDR:

                # print "Found call to ", import_name
                string_arg = get_arguments(xref_cur)

                if string_arg and string_arg not in strings:
                    strings.append(string_arg)

                xref_cur = DnextB(xref_start, xref_cur)

        import_ea += 4

    # now do FLIRT checking
    for function_ea in Functions(SegByName(".text"), SegEnd(start_address)):
        flags = GetFunctionFlags(function_ea)

        if flags & FUNC_LIB:
            lib_name = GetFunctionName(function_ea)

            if len(lib_name) > 1 and "cmp" in lib_name:

                # found one, now find xrefs to it and grab arguments
                xref_start = function_ea
                xref_cur = RfirstB(xref_start)

                while xref_cur != BADADDR:
                    string_arg = get_arguments(xref_cur)

                    if string_arg and string_arg not in strings:
                        strings.append(string_arg)

                    xref_cur = RnextB(xref_start, xref_cur)

    print "Found %d string values used in compares." % len(strings)
    print "-----------------------------------------------------"
    for i in xrange(0, len(strings), 5):
        print strings[i:i + 5]

    return strings


# get file names to save to
constants_file = AskFile(1, ".fuzz_ints", "Enter filename for saving the discovered integers: ")
strings_file = AskFile(1, ".fuzz_strings", "Enter filename for saving the discovered strings: ")

# get integers
start_address = SegByName(".text")
constants = find_ints(start_address)
constants = map(lambda x: "0x%x" % x, constants)

print

# get strings
start_address = SegByName(".idata")
strings = find_strings(start_address)

# write integers
fh = open(constants_file, 'w+')
for c in constants:
    fh.write(c + "\n")
fh.close()

# write strings
fh = open(strings_file, 'w+')
for s in strings:
    fh.write(s + "\n")
fh.close()

print "Done."
