import socket
import platform
import ctypes as c

# noinspection PyPep8Naming
def get_max_udp_size():
    """
    Crazy CTypes magic to do a getsockopt() which determines the max UDP payload size in a platform-agnostic way.

        @rtype:  long
        @return: The maximum length of a UDP packet the current platform supports
    """
    windows = platform.uname()[0] == "Windows"
    mac     = platform.uname()[0] == "Darwin"
    linux   = platform.uname()[0] == "Linux"
    lib     = None

    if windows:
        SOL_SOCKET = c.c_int(0xffff)
        SOL_MAX_MSG_SIZE = 0x2003
        lib = c.WinDLL('Ws2_32.dll')
        OPT = c.c_int(SOL_MAX_MSG_SIZE)
    elif linux or mac:
        if mac:
            lib = c.cdll.LoadLibrary('libc.dylib')
        elif linux:
            lib = c.cdll.LoadLibrary('libc.so.6')
        SOL_SOCKET = c.c_int(socket.SOL_SOCKET)
        OPT        = c.c_int(socket.SO_SNDBUF)

    else:
        raise Exception("Unknown platform!")

    ulong_size = c.sizeof(c.c_ulong)
    buf = c.create_string_buffer(ulong_size)
    bufsize = c.c_int(ulong_size)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    lib.getsockopt(
        sock.fileno(),
        SOL_SOCKET,
        OPT,
        buf,
        c.pointer(bufsize)
    )

    return c.c_ulong.from_buffer(buf).value

def calculate_four_byte_padding(string, character="\x00"):
    return character * ((4 - (len(string) & 3)) & 3)
