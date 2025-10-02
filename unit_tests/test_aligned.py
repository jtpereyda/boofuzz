import pytest
from boofuzz import *
from boofuzz.blocks import Aligned
from boofuzz.mutation_context import MutationContext


class TestAligned:
    """Test cases for Aligned block"""

    def test_aligned_basic_padding_needed(self):
        """Test that Aligned adds correct padding when data is not aligned"""
        s_initialize("ALIGNED TEST 1")
        with s_aligned(modulus=4, pattern=b"\x00"):
            s_static(b"AB")  # 2 bytes, needs 2 bytes padding to align to 4
        
        req = s_get("ALIGNED TEST 1")
        result = req.render()
        
        # Should be: b"AB" + b"\x00\x00" = 4 bytes total
        assert len(result) == 4
        assert result == b"AB\x00\x00"

    def test_aligned_already_aligned(self):
        """Test that Aligned adds no padding when data is already aligned"""
        s_initialize("ALIGNED TEST 2")
        with s_aligned(modulus=4, pattern=b"\x00"):
            s_static(b"ABCD")  # 4 bytes, already aligned to 4
        
        req = s_get("ALIGNED TEST 2")
        result = req.render()
        
        # Should be: b"ABCD" with no padding = 4 bytes total
        assert len(result) == 4
        assert result == b"ABCD"

    def test_aligned_modulus_8(self):
        """Test alignment to 8 bytes"""
        s_initialize("ALIGNED TEST 3")
        with s_aligned(modulus=8, pattern=b"\x00"):
            s_static(b"ABC")  # 3 bytes, needs 5 bytes padding to align to 8
        
        req = s_get("ALIGNED TEST 3")
        result = req.render()
        
        # Should be: b"ABC" + b"\x00" * 5 = 8 bytes total
        assert len(result) == 8
        assert result == b"ABC\x00\x00\x00\x00\x00"

    def test_aligned_custom_pattern(self):
        """Test alignment with custom padding pattern"""
        s_initialize("ALIGNED TEST 4")
        with s_aligned(modulus=8, pattern=b"\xff\xfe"):
            s_static(b"ABCDE")  # 5 bytes, needs 3 bytes padding to align to 8
        
        req = s_get("ALIGNED TEST 4")
        result = req.render()
        
        # Should be: b"ABCDE" + b"\xff\xfe\xff" = 8 bytes total
        # Pattern repeats: \xff\xfe (once) + \xff (partial)
        assert len(result) == 8
        assert result == b"ABCDE\xff\xfe\xff"

    def test_aligned_pattern_larger_than_padding(self):
        """Test when pattern is larger than needed padding"""
        s_initialize("ALIGNED TEST 5")
        with s_aligned(modulus=4, pattern=b"\xaa\xbb\xcc"):
            s_static(b"ABC")  # 3 bytes, needs 1 byte padding to align to 4
        
        req = s_get("ALIGNED TEST 5")
        result = req.render()
        
        # Should be: b"ABC" + b"\xaa" = 4 bytes total
        assert len(result) == 4
        assert result == b"ABC\xaa"

    def test_aligned_multiple_children(self):
        """Test alignment with multiple child elements"""
        s_initialize("ALIGNED TEST 6")
        with s_aligned(modulus=4, pattern=b"\x00"):
            s_static(b"A")
            s_static(b"B")
            s_static(b"C")  # Total 3 bytes, needs 1 byte padding
        
        req = s_get("ALIGNED TEST 6")
        result = req.render()
        
        assert len(result) == 4
        assert result == b"ABC\x00"

    def test_aligned_empty_content(self):
        """Test alignment with empty content"""
        s_initialize("ALIGNED TEST 7")
        with s_aligned(modulus=4, pattern=b"\x00"):
            pass  # No children, 0 bytes
        
        req = s_get("ALIGNED TEST 7")
        result = req.render()
        
        # 0 bytes is already aligned to any modulus, no padding needed
        assert len(result) == 0
        assert result == b""

    def test_aligned_modulus_1(self):
        """Test that modulus=1 means everything is already aligned"""
        s_initialize("ALIGNED TEST 8")
        with s_aligned(modulus=1, pattern=b"\x00"):
            s_static(b"XYZ")
        
        req = s_get("ALIGNED TEST 8")
        result = req.render()
        
        # Any length is aligned to 1, no padding
        assert len(result) == 3
        assert result == b"XYZ"
