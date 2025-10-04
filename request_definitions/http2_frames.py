"""
HTTP/2 Frame Primitives for Boofuzz

This module provides basic HTTP/2 frame structures for fuzzing HTTP/2 implementations.
HTTP/2 uses a binary framing layer, which is fundamentally different from HTTP/1.x.

Note: This is a foundational implementation providing frame-level fuzzing capabilities.
Full HTTP/2 protocol support (HPACK compression, stream management, flow control) is not
yet implemented. For comprehensive HTTP/2 fuzzing, consider using these primitives as
building blocks.

Reference: RFC 7540 - Hypertext Transfer Protocol Version 2 (HTTP/2)
https://tools.ietf.org/html/rfc7540

Basic HTTP/2 Frame Format:
+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Frame Payload (0...)                      ...
+---------------------------------------------------------------+

Frame Types:
- DATA (0x0): Conveys arbitrary, variable-length sequences of octets
- HEADERS (0x1): Opens a stream and carries header block fragment
- PRIORITY (0x2): Specifies sender-advised priority of a stream
- RST_STREAM (0x3): Allows immediate termination of a stream
- SETTINGS (0x4): Conveys configuration parameters
- PUSH_PROMISE (0x5): Notifies peer of intention to initiate stream
- PING (0x6): Mechanism for measuring minimal round-trip time
- GOAWAY (0x7): Initiates shutdown of a connection
- WINDOW_UPDATE (0x8): Implements flow control
- CONTINUATION (0x9): Continues sequence of header block fragments
"""

from boofuzz import *

# HTTP/2 Frame Types (RFC 7540, Section 6)
HTTP2_FRAME_DATA = 0x0
HTTP2_FRAME_HEADERS = 0x1
HTTP2_FRAME_PRIORITY = 0x2
HTTP2_FRAME_RST_STREAM = 0x3
HTTP2_FRAME_SETTINGS = 0x4
HTTP2_FRAME_PUSH_PROMISE = 0x5
HTTP2_FRAME_PING = 0x6
HTTP2_FRAME_GOAWAY = 0x7
HTTP2_FRAME_WINDOW_UPDATE = 0x8
HTTP2_FRAME_CONTINUATION = 0x9

# HTTP/2 Frame Flags (RFC 7540, Section 6)
HTTP2_FLAG_END_STREAM = 0x1  # Bit 0
HTTP2_FLAG_END_HEADERS = 0x4  # Bit 2
HTTP2_FLAG_PADDED = 0x8  # Bit 3
HTTP2_FLAG_PRIORITY = 0x20  # Bit 5
HTTP2_FLAG_ACK = 0x1  # Bit 0 (for SETTINGS and PING)

# HTTP/2 Connection Preface (RFC 7540, Section 3.5)
HTTP2_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# List of all blocks defined here (for easy copy/paste)
"""
sess.connect(s_get("HTTP2_CONNECTION_PREFACE"))
sess.connect(s_get("HTTP2_SETTINGS_FRAME"))
sess.connect(s_get("HTTP2_HEADERS_FRAME"))
sess.connect(s_get("HTTP2_DATA_FRAME"))
sess.connect(s_get("HTTP2_PING_FRAME"))
sess.connect(s_get("HTTP2_GOAWAY_FRAME"))
sess.connect(s_get("HTTP2_WINDOW_UPDATE_FRAME"))
sess.connect(s_get("HTTP2_RST_STREAM_FRAME"))
"""


# HTTP/2 Connection Preface
# Must be sent by client at the start of an HTTP/2 connection
s_initialize("HTTP2_CONNECTION_PREFACE")
s_static(HTTP2_CONNECTION_PREFACE)


# HTTP/2 SETTINGS Frame (Type 0x4)
# Used to communicate configuration parameters
s_initialize("HTTP2_SETTINGS_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit) - will be calculated from payload
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - SETTINGS
    s_byte(HTTP2_FRAME_SETTINGS, name="frame_type", fuzzable=False)
    # Flags (8-bit)
    s_byte(0x0, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit) - must be 0x0 for SETTINGS
    s_dword(0x0, name="stream_id", endian=">", fuzzable=False)
s_block_end()

# Frame Payload - SETTINGS parameters (6 bytes per parameter)
if s_block_start("payload"):
    # SETTINGS_HEADER_TABLE_SIZE (0x1) - default 4096
    s_word(0x1, name="setting_id_1", endian=">")
    s_dword(4096, name="setting_value_1", endian=">")

    # SETTINGS_ENABLE_PUSH (0x2) - default 1
    s_word(0x2, name="setting_id_2", endian=">")
    s_dword(1, name="setting_value_2", endian=">")

    # SETTINGS_MAX_CONCURRENT_STREAMS (0x3)
    s_word(0x3, name="setting_id_3", endian=">")
    s_dword(100, name="setting_value_3", endian=">")

    # SETTINGS_INITIAL_WINDOW_SIZE (0x4) - default 65535
    s_word(0x4, name="setting_id_4", endian=">")
    s_dword(65535, name="setting_value_4", endian=">")

    # SETTINGS_MAX_FRAME_SIZE (0x5) - default 16384
    s_word(0x5, name="setting_id_5", endian=">")
    s_dword(16384, name="setting_value_5", endian=">")

    # SETTINGS_MAX_HEADER_LIST_SIZE (0x6)
    s_word(0x6, name="setting_id_6", endian=">")
    s_dword(8192, name="setting_value_6", endian=">")
s_block_end()


# HTTP/2 HEADERS Frame (Type 0x1)
# Opens a stream and carries header block fragment
s_initialize("HTTP2_HEADERS_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit)
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - HEADERS
    s_byte(HTTP2_FRAME_HEADERS, name="frame_type", fuzzable=False)
    # Flags (8-bit) - END_HEADERS
    s_byte(HTTP2_FLAG_END_HEADERS, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit)
    s_dword(1, name="stream_id", endian=">")
s_block_end()

# Frame Payload - Header Block Fragment (simplified - should use HPACK)
if s_block_start("payload"):
    # Note: In a real HTTP/2 implementation, headers would be HPACK compressed
    # This is a simplified version for basic fuzzing
    s_string("\x82\x86\x84\x41\x8a\x0b\x84\x9d\x29\xac\x4b\x8f\xa7\x0e\x9a\xc2\xca\x7f\x84\x87", name="header_block")
s_block_end()


# HTTP/2 DATA Frame (Type 0x0)
# Conveys arbitrary, variable-length sequences of octets
s_initialize("HTTP2_DATA_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit)
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - DATA
    s_byte(HTTP2_FRAME_DATA, name="frame_type", fuzzable=False)
    # Flags (8-bit) - END_STREAM
    s_byte(HTTP2_FLAG_END_STREAM, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit)
    s_dword(1, name="stream_id", endian=">")
s_block_end()

# Frame Payload
if s_block_start("payload"):
    s_string("Hello, HTTP/2!", name="data")
s_block_end()


# HTTP/2 PING Frame (Type 0x6)
# Mechanism for measuring minimal round-trip time
s_initialize("HTTP2_PING_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit) - PING frames always have 8-byte payload
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - PING
    s_byte(HTTP2_FRAME_PING, name="frame_type", fuzzable=False)
    # Flags (8-bit)
    s_byte(0x0, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit) - must be 0x0 for PING
    s_dword(0x0, name="stream_id", endian=">", fuzzable=False)
s_block_end()

# Frame Payload (8 bytes - opaque data)
if s_block_start("payload"):
    s_qword(0x0123456789abcdef, name="opaque_data", endian=">")
s_block_end()


# HTTP/2 GOAWAY Frame (Type 0x7)
# Initiates shutdown of a connection
s_initialize("HTTP2_GOAWAY_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit)
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - GOAWAY
    s_byte(HTTP2_FRAME_GOAWAY, name="frame_type", fuzzable=False)
    # Flags (8-bit)
    s_byte(0x0, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit) - must be 0x0 for GOAWAY
    s_dword(0x0, name="stream_id", endian=">", fuzzable=False)
s_block_end()

# Frame Payload
if s_block_start("payload"):
    # Reserved (1-bit) + Last-Stream-ID (31-bit)
    s_dword(0, name="last_stream_id", endian=">")
    # Error Code (32-bit)
    s_dword(0, name="error_code", endian=">")
    # Additional Debug Data (optional)
    s_string("", name="debug_data")
s_block_end()


# HTTP/2 WINDOW_UPDATE Frame (Type 0x8)
# Implements flow control
s_initialize("HTTP2_WINDOW_UPDATE_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit) - WINDOW_UPDATE frames always have 4-byte payload
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - WINDOW_UPDATE
    s_byte(HTTP2_FRAME_WINDOW_UPDATE, name="frame_type", fuzzable=False)
    # Flags (8-bit)
    s_byte(0x0, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit)
    s_dword(0, name="stream_id", endian=">")
s_block_end()

# Frame Payload
if s_block_start("payload"):
    # Reserved (1-bit) + Window Size Increment (31-bit)
    s_dword(65535, name="window_size_increment", endian=">")
s_block_end()


# HTTP/2 RST_STREAM Frame (Type 0x3)
# Allows immediate termination of a stream
s_initialize("HTTP2_RST_STREAM_FRAME")

# Frame Header (9 bytes)
if s_block_start("frame_header"):
    # Length (24-bit) - RST_STREAM frames always have 4-byte payload
    s_size("payload", length=3, endian=">", fuzzable=False)
    # Type (8-bit) - RST_STREAM
    s_byte(HTTP2_FRAME_RST_STREAM, name="frame_type", fuzzable=False)
    # Flags (8-bit)
    s_byte(0x0, name="flags")
    # Reserved (1-bit) + Stream Identifier (31-bit) - must not be 0x0
    s_dword(1, name="stream_id", endian=">")
s_block_end()

# Frame Payload
if s_block_start("payload"):
    # Error Code (32-bit)
    s_dword(0, name="error_code", endian=">")
s_block_end()
