from boofuzz import *


def run():
    signed_tests()
    string_tests()
    # fuzz_extension_tests()

    # clear out the requests.
    blocks.REQUESTS = {}
    blocks.CURRENT = None


def signed_tests():
    s_initialize("UNIT TEST 1")
    s_byte(0, output_format="ascii", signed=True, name="byte_1")
    s_byte(0xff / 2, output_format="ascii", signed=True, name="byte_2")
    s_byte(0xff / 2 + 1, output_format="ascii", signed=True, name="byte_3")
    s_byte(0xff, output_format="ascii", signed=True, name="byte_4")

    s_word(0, output_format="ascii", signed=True, name="word_1")
    s_word(0xffff / 2, output_format="ascii", signed=True, name="word_2")
    s_word(0xffff / 2 + 1, output_format="ascii", signed=True, name="word_3")
    s_word(0xffff, output_format="ascii", signed=True, name="word_4")

    s_dword(0, output_format="ascii", signed=True, name="dword_1")
    s_dword(0xffffffff / 2, output_format="ascii", signed=True, name="dword_2")
    s_dword(0xffffffff / 2 + 1, output_format="ascii", signed=True, name="dword_3")
    s_dword(0xffffffff, output_format="ascii", signed=True, name="dword_4")

    s_qword(0, output_format="ascii", signed=True, name="qword_1")
    s_qword(0xffffffffffffffff / 2, output_format="ascii", signed=True, name="qword_2")
    s_qword(0xffffffffffffffff / 2 + 1, output_format="ascii", signed=True, name="qword_3")
    s_qword(0xffffffffffffffff, output_format="ascii", signed=True, name="qword_4")

    req = s_get("UNIT TEST 1")

    assert (req.names["byte_1"].render() == "0")
    assert (req.names["byte_2"].render() == "127")
    assert (req.names["byte_3"].render() == "-128")
    assert (req.names["byte_4"].render() == "-1")
    assert (req.names["word_1"].render() == "0")
    assert (req.names["word_2"].render() == "32767")
    assert (req.names["word_3"].render() == "-32768")
    assert (req.names["word_4"].render() == "-1")
    assert (req.names["dword_1"].render() == "0")
    assert (req.names["dword_2"].render() == "2147483647")
    assert (req.names["dword_3"].render() == "-2147483648")
    assert (req.names["dword_4"].render() == "-1")
    assert (req.names["qword_1"].render() == "0")
    assert (req.names["qword_2"].render() == "9223372036854775807")
    assert (req.names["qword_3"].render() == "-9223372036854775808")
    assert (req.names["qword_4"].render() == "-1")


def string_tests():
    s_initialize("STRING UNIT TEST 1")
    s_string("foo", size=200, name="sized_string")

    req = s_get("STRING UNIT TEST 1")

    assert (len(req.names["sized_string"].render()) == 200)

    # check that string padding and truncation are working correctly.
    for i in xrange(0, 50):
        s_mutate()
        assert (len(req.names["sized_string"].render()) == 200)


def fuzz_extension_tests():
    import shutil

    # backup existing fuzz extension libraries.
    try:
        shutil.move(".fuzz_strings", ".fuzz_strings_backup")
        shutil.move(".fuzz_ints", ".fuzz_ints_backup")
    except Exception:
        pass

    # create extension libraries for unit test.
    fh = open(".fuzz_strings", "w+")
    fh.write("pedram\n")
    fh.write("amini\n")
    fh.close()

    fh = open(".fuzz_ints", "w+")
    fh.write("deadbeef\n")
    fh.write("0xc0cac01a\n")
    fh.close()

    s_initialize("EXTENSION TEST")

    s_string("foo", name="string")
    s_int(200, name="int")
    s_char(ord("A"), name="char")

    req = s_get("EXTENSION TEST")

    # these should be here now.
    assert (0xdeadbeef in req.names["int"]._fuzz_library)
    assert (0xc0cac01a in req.names["int"]._fuzz_library)

    # these should not as a char is too small to store them.
    assert (0xdeadbeef not in req.names["char"]._fuzz_library)
    assert (0xc0cac01a not in req.names["char"]._fuzz_library)

    # these should be here now.
    assert ("pedram" in req.names["string"]._fuzz_library)
    assert ("amini" in req.names["string"]._fuzz_library)

    # restore existing fuzz extension libraries.
    try:
        shutil.move(".fuzz_strings_backup", ".fuzz_strings")
        shutil.move(".fuzz_ints_backup", ".fuzz_ints")
    except Exception:
        pass