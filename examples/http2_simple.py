#!/usr/bin/env python3
"""
HTTP/2 Fuzzing Example

This example demonstrates how to use boofuzz to fuzz HTTP/2 endpoints.
HTTP/2 uses a binary framing protocol, which is different from HTTP/1.x.

Prerequisites:
- An HTTP/2 server running on localhost:443 (or modify target below)
- SSL/TLS support (HTTP/2 typically requires ALPN negotiation)

Note: This is a basic example showing frame-level fuzzing. For production use,
you would need to implement:
1. ALPN negotiation for HTTP/2
2. HPACK header compression/decompression
3. Stream state management
4. Flow control
5. Server response parsing

HTTP/2 Connection Flow:
1. Send HTTP/2 connection preface
2. Exchange SETTINGS frames
3. Send HEADERS frame to initiate request
4. Optionally send DATA frame(s)
5. Receive response frames

For more information on HTTP/2:
- RFC 7540: https://tools.ietf.org/html/rfc7540
- HTTP/2 FAQ: https://http2.github.io/faq/
"""

from boofuzz import *  # noqa: F401,F403,E402
import sys
import os

# Add request_definitions to path to import HTTP/2 frames
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'request_definitions'))


def main():
    """
    Main fuzzing function.

    This sets up a basic HTTP/2 fuzzing session targeting an HTTP/2 server.
    The session will fuzz various HTTP/2 frames in sequence.
    """
    # Note: For real HTTP/2, you typically need SSL/TLS with ALPN
    # Consider using SSLSocketConnection if your target requires it
    session = Session(
        target=Target(
            connection=TCPSocketConnection("127.0.0.1", 443)
        ),
        # Uncomment below for SSL/TLS support:
        # target=Target(
        #     connection=SSLSocketConnection("127.0.0.1", 443)
        # ),
    )

    define_http2_session(session)

    session.fuzz()


def define_http2_session(session):
    """
    Define HTTP/2 protocol structure for fuzzing.

    This creates a basic HTTP/2 session structure:
    1. Connection Preface
    2. SETTINGS frame
    3. HEADERS frame (initiating a request)
    4. Optional DATA frame

    Args:
        session: boofuzz Session object
    """
    # Import the HTTP/2 frame definitions
    import http2_frames  # noqa: F401

    # HTTP/2 Connection Preface (required to initiate HTTP/2)
    preface = s_get("HTTP2_CONNECTION_PREFACE")

    # Initial SETTINGS frame (required after preface)
    settings = s_get("HTTP2_SETTINGS_FRAME")

    # HEADERS frame (opens a stream and sends headers)
    headers = s_get("HTTP2_HEADERS_FRAME")

    # DATA frame (optional payload)
    data = s_get("HTTP2_DATA_FRAME")

    # Build the request graph
    # The connection preface must be sent first
    session.connect(preface)

    # SETTINGS frame follows the preface
    session.connect(preface, settings)

    # HEADERS frame can be sent after SETTINGS
    session.connect(settings, headers)

    # DATA frame can be sent after HEADERS
    session.connect(headers, data)


def define_http2_control_frames(session):
    """
    Define HTTP/2 control frame fuzzing.

    This focuses on fuzzing HTTP/2 control frames like PING, GOAWAY, etc.

    Args:
        session: boofuzz Session object
    """
    import http2_frames  # noqa: F401

    # PING frame for measuring round-trip time
    ping = s_get("HTTP2_PING_FRAME")

    # WINDOW_UPDATE for flow control
    window_update = s_get("HTTP2_WINDOW_UPDATE_FRAME")

    # GOAWAY to close connection
    goaway = s_get("HTTP2_GOAWAY_FRAME")

    # RST_STREAM to terminate a stream
    rst_stream = s_get("HTTP2_RST_STREAM_FRAME")

    # Create separate fuzzing sessions for each control frame
    session.connect(s_get("HTTP2_CONNECTION_PREFACE"))
    session.connect(s_get("HTTP2_CONNECTION_PREFACE"), s_get("HTTP2_SETTINGS_FRAME"))
    session.connect(s_get("HTTP2_SETTINGS_FRAME"), ping)
    session.connect(s_get("HTTP2_SETTINGS_FRAME"), window_update)
    session.connect(s_get("HTTP2_SETTINGS_FRAME"), goaway)
    session.connect(s_get("HTTP2_SETTINGS_FRAME"), rst_stream)


def fuzz_http2_settings_parameters():
    """
    Example of fuzzing specific HTTP/2 SETTINGS parameters.

    This creates a custom SETTINGS frame with fuzzable parameters.
    Useful for testing server parameter handling.
    """
    s_initialize("CUSTOM_HTTP2_SETTINGS")

    if s_block_start("frame_header"):
        s_size("payload", length=3, endian=">", fuzzable=False)
        s_byte(0x4, name="frame_type", fuzzable=False)  # SETTINGS
        s_byte(0x0, name="flags")
        s_dword(0x0, name="stream_id", endian=">", fuzzable=False)
    s_block_end()

    if s_block_start("payload"):
        # Fuzz SETTINGS_MAX_FRAME_SIZE
        s_word(0x5, name="setting_id", endian=">", fuzzable=False)
        # Valid range: 16384 to 16777215, let's fuzz it!
        s_dword(16384, name="max_frame_size", endian=">")
    s_block_end()

    return s_get("CUSTOM_HTTP2_SETTINGS")


if __name__ == "__main__":
    # Check if we want to fuzz control frames instead
    if len(sys.argv) > 1 and sys.argv[1] == "--control-frames":
        print("Fuzzing HTTP/2 control frames...")
        session = Session(
            target=Target(
                connection=TCPSocketConnection("127.0.0.1", 443)
            ),
        )
        define_http2_control_frames(session)
        session.fuzz()
    else:
        print("Fuzzing HTTP/2 data frames...")
        print("Use --control-frames to fuzz control frames instead")
        main()
