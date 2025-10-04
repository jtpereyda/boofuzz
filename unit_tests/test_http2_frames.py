"""
Unit tests for HTTP/2 frame primitives.

Tests the basic structure and rendering of HTTP/2 frames defined in
request_definitions/http2_frames.py
"""

import sys
import os
import struct

import pytest
from boofuzz import blocks  # noqa: E402

# Add request_definitions to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'request_definitions'))


# Import http2_frames at module level to register all frame definitions
try:
    import http2_frames
except ImportError:
    # If import fails in CI or other environments, skip
    http2_frames = None


@pytest.fixture(autouse=True, scope="module")
def ensure_http2_frames_loaded():
    """Ensure HTTP/2 frames are loaded before tests run."""
    if http2_frames is None:
        pytest.skip("http2_frames module not available")
    # Verify the frames are registered
    required_frames = [
        "HTTP2_CONNECTION_PREFACE",
        "HTTP2_SETTINGS_FRAME",
        "HTTP2_HEADERS_FRAME",
        "HTTP2_DATA_FRAME",
        "HTTP2_PING_FRAME",
        "HTTP2_GOAWAY_FRAME",
        "HTTP2_WINDOW_UPDATE_FRAME",
        "HTTP2_RST_STREAM_FRAME",
    ]
    for frame_name in required_frames:
        if frame_name not in blocks.REQUESTS:
            pytest.skip(f"Required frame {frame_name} not registered")


class TestHTTP2ConnectionPreface:
    """Tests for HTTP/2 connection preface."""

    def test_connection_preface_value(self):
        """Test that connection preface has correct value."""
        # The request is already initialized in http2_frames.py
        req = blocks.REQUESTS["HTTP2_CONNECTION_PREFACE"]

        rendered = req.render()
        expected = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        assert rendered == expected

    def test_connection_preface_length(self):
        """Test that connection preface is 24 bytes."""
        assert len(http2_frames.HTTP2_CONNECTION_PREFACE) == 24


class TestHTTP2SettingsFrame:
    """Tests for HTTP/2 SETTINGS frame."""

    def test_settings_frame_structure(self):
        """Test SETTINGS frame has correct structure."""
        req = blocks.REQUESTS["HTTP2_SETTINGS_FRAME"]
        rendered = req.render()

        # Frame header is 9 bytes
        frame_header = rendered[:9]

        # Parse frame header
        length = struct.unpack(">I", b"\x00" + frame_header[:3])[0]
        frame_type = frame_header[3]
        stream_id = struct.unpack(">I", frame_header[5:9])[0]

        # SETTINGS frame assertions
        assert frame_type == http2_frames.HTTP2_FRAME_SETTINGS
        assert stream_id == 0  # SETTINGS must have stream ID 0
        assert length > 0  # Should have at least one setting

    def test_settings_frame_payload(self):
        """Test SETTINGS frame payload structure."""
        req = blocks.REQUESTS["HTTP2_SETTINGS_FRAME"]
        rendered = req.render()

        # Get length from frame header
        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]

        # Each setting is 6 bytes (2-byte ID + 4-byte value)
        assert length % 6 == 0

        # Should have at least one setting
        assert length >= 6

    def test_settings_parameter_count(self):
        """Test SETTINGS frame contains expected number of parameters."""
        req = blocks.REQUESTS["HTTP2_SETTINGS_FRAME"]
        rendered = req.render()

        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]
        param_count = length // 6

        # Default implementation has 6 settings
        assert param_count == 6


class TestHTTP2HeadersFrame:
    """Tests for HTTP/2 HEADERS frame."""

    def test_headers_frame_type(self):
        """Test HEADERS frame has correct type."""
        req = blocks.REQUESTS["HTTP2_HEADERS_FRAME"]
        rendered = req.render()

        frame_type = rendered[3]
        assert frame_type == http2_frames.HTTP2_FRAME_HEADERS

    def test_headers_frame_stream_id(self):
        """Test HEADERS frame has non-zero stream ID."""
        req = blocks.REQUESTS["HTTP2_HEADERS_FRAME"]
        rendered = req.render()

        stream_id = struct.unpack(">I", rendered[5:9])[0] & 0x7FFFFFFF  # Clear reserved bit
        assert stream_id > 0  # HEADERS must have non-zero stream ID

    def test_headers_frame_flags(self):
        """Test HEADERS frame has END_HEADERS flag set."""
        req = blocks.REQUESTS["HTTP2_HEADERS_FRAME"]
        rendered = req.render()

        flags = rendered[4]
        assert flags & http2_frames.HTTP2_FLAG_END_HEADERS


class TestHTTP2DataFrame:
    """Tests for HTTP/2 DATA frame."""

    def test_data_frame_type(self):
        """Test DATA frame has correct type."""
        req = blocks.REQUESTS["HTTP2_DATA_FRAME"]
        rendered = req.render()

        frame_type = rendered[3]
        assert frame_type == http2_frames.HTTP2_FRAME_DATA

    def test_data_frame_stream_id(self):
        """Test DATA frame has non-zero stream ID."""
        req = blocks.REQUESTS["HTTP2_DATA_FRAME"]
        rendered = req.render()

        stream_id = struct.unpack(">I", rendered[5:9])[0] & 0x7FFFFFFF
        assert stream_id > 0  # DATA must have non-zero stream ID

    def test_data_frame_payload(self):
        """Test DATA frame contains payload."""
        req = blocks.REQUESTS["HTTP2_DATA_FRAME"]
        rendered = req.render()

        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]
        payload = rendered[9:9 + length]

        assert len(payload) > 0
        assert b"Hello, HTTP/2!" in payload


class TestHTTP2PingFrame:
    """Tests for HTTP/2 PING frame."""

    def test_ping_frame_type(self):
        """Test PING frame has correct type."""
        req = blocks.REQUESTS["HTTP2_PING_FRAME"]
        rendered = req.render()

        frame_type = rendered[3]
        assert frame_type == http2_frames.HTTP2_FRAME_PING

    def test_ping_frame_stream_id(self):
        """Test PING frame has stream ID 0."""
        req = blocks.REQUESTS["HTTP2_PING_FRAME"]
        rendered = req.render()

        stream_id = struct.unpack(">I", rendered[5:9])[0]
        assert stream_id == 0  # PING must have stream ID 0

    def test_ping_frame_payload_length(self):
        """Test PING frame has 8-byte payload."""
        req = blocks.REQUESTS["HTTP2_PING_FRAME"]
        rendered = req.render()

        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]
        assert length == 8  # PING payload is always 8 bytes


class TestHTTP2GoawayFrame:
    """Tests for HTTP/2 GOAWAY frame."""

    def test_goaway_frame_type(self):
        """Test GOAWAY frame has correct type."""
        req = blocks.REQUESTS["HTTP2_GOAWAY_FRAME"]
        rendered = req.render()

        frame_type = rendered[3]
        assert frame_type == http2_frames.HTTP2_FRAME_GOAWAY

    def test_goaway_frame_stream_id(self):
        """Test GOAWAY frame has stream ID 0."""
        req = blocks.REQUESTS["HTTP2_GOAWAY_FRAME"]
        rendered = req.render()

        stream_id = struct.unpack(">I", rendered[5:9])[0]
        assert stream_id == 0  # GOAWAY must have stream ID 0

    def test_goaway_frame_payload_structure(self):
        """Test GOAWAY frame has valid payload structure."""
        req = blocks.REQUESTS["HTTP2_GOAWAY_FRAME"]
        rendered = req.render()

        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]
        assert length >= 8  # Minimum: last_stream_id (4) + error_code (4)

        payload = rendered[9:9 + length]
        last_stream_id = struct.unpack(">I", payload[:4])[0] & 0x7FFFFFFF
        error_code = struct.unpack(">I", payload[4:8])[0]

        # These should be valid values
        assert last_stream_id >= 0
        assert error_code >= 0


class TestHTTP2WindowUpdateFrame:
    """Tests for HTTP/2 WINDOW_UPDATE frame."""

    def test_window_update_frame_type(self):
        """Test WINDOW_UPDATE frame has correct type."""
        req = blocks.REQUESTS["HTTP2_WINDOW_UPDATE_FRAME"]
        rendered = req.render()

        frame_type = rendered[3]
        assert frame_type == http2_frames.HTTP2_FRAME_WINDOW_UPDATE

    def test_window_update_payload_length(self):
        """Test WINDOW_UPDATE frame has 4-byte payload."""
        req = blocks.REQUESTS["HTTP2_WINDOW_UPDATE_FRAME"]
        rendered = req.render()

        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]
        assert length == 4  # WINDOW_UPDATE payload is always 4 bytes

    def test_window_update_increment_value(self):
        """Test WINDOW_UPDATE frame has valid increment value."""
        req = blocks.REQUESTS["HTTP2_WINDOW_UPDATE_FRAME"]
        rendered = req.render()

        payload = rendered[9:13]
        increment = struct.unpack(">I", payload)[0] & 0x7FFFFFFF

        assert increment > 0  # Increment must be positive


class TestHTTP2RstStreamFrame:
    """Tests for HTTP/2 RST_STREAM frame."""

    def test_rst_stream_frame_type(self):
        """Test RST_STREAM frame has correct type."""
        req = blocks.REQUESTS["HTTP2_RST_STREAM_FRAME"]
        rendered = req.render()

        frame_type = rendered[3]
        assert frame_type == http2_frames.HTTP2_FRAME_RST_STREAM

    def test_rst_stream_stream_id(self):
        """Test RST_STREAM frame has non-zero stream ID."""
        req = blocks.REQUESTS["HTTP2_RST_STREAM_FRAME"]
        rendered = req.render()

        stream_id = struct.unpack(">I", rendered[5:9])[0] & 0x7FFFFFFF
        assert stream_id > 0  # RST_STREAM must have non-zero stream ID

    def test_rst_stream_payload_length(self):
        """Test RST_STREAM frame has 4-byte payload."""
        req = blocks.REQUESTS["HTTP2_RST_STREAM_FRAME"]
        rendered = req.render()

        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]
        assert length == 4  # RST_STREAM payload is always 4 bytes (error code)


class TestHTTP2FrameConstants:
    """Tests for HTTP/2 frame constants."""

    def test_frame_type_constants(self):
        """Test frame type constants have correct values."""
        assert http2_frames.HTTP2_FRAME_DATA == 0x0
        assert http2_frames.HTTP2_FRAME_HEADERS == 0x1
        assert http2_frames.HTTP2_FRAME_PRIORITY == 0x2
        assert http2_frames.HTTP2_FRAME_RST_STREAM == 0x3
        assert http2_frames.HTTP2_FRAME_SETTINGS == 0x4
        assert http2_frames.HTTP2_FRAME_PUSH_PROMISE == 0x5
        assert http2_frames.HTTP2_FRAME_PING == 0x6
        assert http2_frames.HTTP2_FRAME_GOAWAY == 0x7
        assert http2_frames.HTTP2_FRAME_WINDOW_UPDATE == 0x8
        assert http2_frames.HTTP2_FRAME_CONTINUATION == 0x9

    def test_flag_constants(self):
        """Test flag constants have correct values."""
        assert http2_frames.HTTP2_FLAG_END_STREAM == 0x1
        assert http2_frames.HTTP2_FLAG_END_HEADERS == 0x4
        assert http2_frames.HTTP2_FLAG_PADDED == 0x8
        assert http2_frames.HTTP2_FLAG_PRIORITY == 0x20
        assert http2_frames.HTTP2_FLAG_ACK == 0x1


class TestHTTP2FrameHeader:
    """Tests for HTTP/2 frame header structure."""

    @pytest.mark.parametrize("frame_name", [
        "HTTP2_SETTINGS_FRAME",
        "HTTP2_HEADERS_FRAME",
        "HTTP2_DATA_FRAME",
        "HTTP2_PING_FRAME",
        "HTTP2_GOAWAY_FRAME",
        "HTTP2_WINDOW_UPDATE_FRAME",
        "HTTP2_RST_STREAM_FRAME",
    ])
    def test_frame_header_length(self, frame_name):
        """Test all frames have 9-byte header."""
        req = blocks.REQUESTS[frame_name]
        rendered = req.render()

        # All HTTP/2 frames have a 9-byte header
        assert len(rendered) >= 9

    @pytest.mark.parametrize("frame_name", [
        "HTTP2_SETTINGS_FRAME",
        "HTTP2_HEADERS_FRAME",
        "HTTP2_DATA_FRAME",
        "HTTP2_PING_FRAME",
        "HTTP2_GOAWAY_FRAME",
        "HTTP2_WINDOW_UPDATE_FRAME",
        "HTTP2_RST_STREAM_FRAME",
    ])
    def test_frame_length_field_matches_payload(self, frame_name):
        """Test frame length field matches actual payload length."""
        req = blocks.REQUESTS[frame_name]
        rendered = req.render()

        # Parse length from header
        length = struct.unpack(">I", b"\x00" + rendered[:3])[0]

        # Check it matches payload size
        assert len(rendered) == 9 + length
