import unittest

import pytest

from boofuzz import *


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


class TestLegos(unittest.TestCase):
    def test_tag(self):
        s_initialize("UNIT TEST TAG 1")
        s_lego("tag", value="pedram")

        req = s_get("UNIT TEST TAG 1")

        self.assertGreater(req.num_mutations(), 0)

    def test_ndr_string(self):
        s_initialize("UNIT TEST NDR 1")
        s_lego("ndr_string", value="pedram")

        s_get("UNIT TEST NDR 1")
        # TODO: unfinished!
        # print(req.render())

    @pytest.mark.skip(reason="BER is broken")
    def test_ber(self):
        s_initialize("UNIT TEST BER 1")
        s_lego("ber_string", value="pedram")
        s_get("UNIT TEST BER 1")
        self.assertEqual(s_render(), "\x04\x84\x00\x00\x00\x06\x70\x65\x64\x72\x61\x6d")
        s_mutate()
        self.assertEqual(s_render(), "\x04\x84\x00\x00\x00\x00\x70\x65\x64\x72\x61\x6d")

        s_initialize("UNIT TEST BER 2")
        s_lego("ber_integer", value=0xDEADBEEF)
        s_get("UNIT TEST BER 2")
        self.assertEqual(s_render(), "\x02\x04\xde\xad\xbe\xef")
        s_mutate()
        self.assertEqual(s_render(), "\x02\x04\x00\x00\x00\x00")
        s_mutate()
        self.assertEqual(s_render(), "\x02\x04\x00\x00\x00\x01")


if __name__ == "__main__":
    unittest.main()
