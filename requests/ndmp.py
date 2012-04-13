from sulley import *

import struct
import time

ndmp_messages = \
[
            # Connect Interface
    0x900,  # NDMP_CONNECT_OPEN
    0x901,  # NDMP_CONECT_CLIENT_AUTH
    0x902,  # NDMP_CONNECT_CLOSE
    0x903,  # NDMP_CONECT_SERVER_AUTH

            # Config Interface
    0x100,  # NDMP_CONFIG_GET_HOST_INFO
    0x102,  # NDMP_CONFIG_GET_CONNECTION_TYPE
    0x103,  # NDMP_CONFIG_GET_AUTH_ATTR
    0x104,  # NDMP_CONFIG_GET_BUTYPE_INFO
    0x105,  # NDMP_CONFIG_GET_FS_INFO
    0x106,  # NDMP_CONFIG_GET_TAPE_INFO
    0x107,  # NDMP_CONFIG_GET_SCSI_INFO
    0x108,  # NDMP_CONFIG_GET_SERVER_INFO

            # SCSI Interface
    0x200,  # NDMP_SCSI_OPEN
    0x201,  # NDMP_SCSI_CLOSE
    0x202,  # NDMP_SCSI_GET_STATE
    0x203,  # NDMP_SCSI_SET_TARGET
    0x204,  # NDMP_SCSI_RESET_DEVICE
    0x205,  # NDMP_SCSI_RESET_BUS
    0x206,  # NDMP_SCSI_EXECUTE_CDB

            # Tape Interface
    0x300,  # NDMP_TAPE_OPEN
    0x301,  # NDMP_TAPE_CLOSE
    0x302,  # NDMP_TAPE_GET_STATE
    0x303,  # NDMP_TAPE_MTIO
    0x304,  # NDMP_TAPE_WRITE
    0x305,  # NDMP_TAPE_READ
    0x307,  # NDMP_TAPE_EXECUTE_CDB

            # Data Interface
    0x400,  # NDMP_DATA_GET_STATE
    0x401,  # NDMP_DATA_START_BACKUP
    0x402,  # NDMP_DATA_START_RECOVER
    0x403,  # NDMP_DATA_ABORT
    0x404,  # NDMP_DATA_GET_ENV
    0x407,  # NDMP_DATA_STOP
    0x409,  # NDMP_DATA_LISTEN
    0x40a,  # NDMP_DATA_CONNECT

            # Notify Interface
    0x501,  # NDMP_NOTIFY_DATA_HALTED
    0x502,  # NDMP_NOTIFY_CONNECTED
    0x503,  # NDMP_NOTIFY_MOVER_HALTED
    0x504,  # NDMP_NOTIFY_MOVER_PAUSED
    0x505,  # NDMP_NOTIFY_DATA_READ

            # Log Interface
    0x602,  # NDMP_LOG_FILES
    0x603,  # NDMP_LOG_MESSAGE

            # File History Interface
    0x703,  # NDMP_FH_ADD_FILE
    0x704,  # NDMP_FH_ADD_DIR
    0x705,  # NDMP_FH_ADD_NODE

            # Mover Interface
    0xa00,  # NDMP_MOVER_GET_STATE
    0xa01,  # NDMP_MOVER_LISTEN
    0xa02,  # NDMP_MOVER_CONTINUE
    0xa03,  # NDMP_MOVER_ABORT
    0xa04,  # NDMP_MOVER_STOP
    0xa05,  # NDMP_MOVER_SET_WINDOW
    0xa06,  # NDMP_MOVER_READ
    0xa07,  # NDMP_MOVER_CLOSE
    0xa08,  # NDMP_MOVER_SET_RECORD_SIZE
    0xa09,  # NDMP_MOVER_CONNECT

            # Reserved for the vendor specific usage (from 0xf000 to 0xffff)
    0xf000, # NDMP_VENDORS_BASE

            # Reserved for Prototyping (from 0xff00 to 0xffff)
    0xff00, # NDMP_RESERVED_BASE
]


########################################################################################################################
s_initialize("Veritas NDMP_CONECT_CLIENT_AUTH")

# the first bit is the last frag flag, we'll always set it and truncate our size to 3 bytes.
# 3 bytes of size gives us a max 16mb ndmp message, plenty of space.
s_static("\x80")
s_size("request", length=3, endian=">")

if s_block_start("request"):
    if s_block_start("ndmp header"):
        s_static(struct.pack(">L", 1),           name="sequence")
        s_static(struct.pack(">L", time.time()), name="timestamp")
        s_static(struct.pack(">L", 0),           name="message type")    # request (0)
        s_static(struct.pack(">L", 0x901),       name="NDMP_CONECT_CLIENT_AUTH")
        s_static(struct.pack(">L", 1),           name="reply sequence")
        s_static(struct.pack(">L", 0),           name="error")
    s_block_end("ndmp header")

    s_group("auth types", values=[struct.pack(">L", 190), struct.pack(">L", 5), struct.pack(">L", 4)])

    if s_block_start("body", group="auth types"):
        # do random data.
        s_random(0, min_length=1000, max_length=50000, num_mutations=500)

        # random valid XDR string.
        #s_lego("xdr_string", "pedram")
    s_block_end("body")
s_block_end("request")


########################################################################################################################
s_initialize("Veritas Proprietary Message Types")

# the first bit is the last frag flag, we'll always set it and truncate our size to 3 bytes.
# 3 bytes of size gives us a max 16mb ndmp message, plenty of space.
s_static("\x80")
s_size("request", length=3, endian=">")

if s_block_start("request"):
    if s_block_start("ndmp header"):
        s_static(struct.pack(">L", 1),           name="sequence")
        s_static(struct.pack(">L", time.time()), name="timestamp")
        s_static(struct.pack(">L", 0),           name="message type")    # request (0)

        s_group("prop ops", values = \
            [
                struct.pack(">L", 0xf315),      # file list?
                struct.pack(">L", 0xf316),
                struct.pack(">L", 0xf317),
                struct.pack(">L", 0xf200),      #
                struct.pack(">L", 0xf201),
                struct.pack(">L", 0xf202),
                struct.pack(">L", 0xf31b),
                struct.pack(">L", 0xf270),      # send strings like NDMP_PROP_PEER_PROTOCOL_VERSION
                struct.pack(">L", 0xf271),
                struct.pack(">L", 0xf33b),
                struct.pack(">L", 0xf33c),
            ])

        s_static(struct.pack(">L", 1),           name="reply sequence")
        s_static(struct.pack(">L", 0),           name="error")
    s_block_end("ndmp header")

    if s_block_start("body", group="prop ops"):
        s_random("\x00\x00\x00\x00", min_length=1000, max_length=50000, num_mutations=100)
    s_block_end("body")
s_block_end("request")