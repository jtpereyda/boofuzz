import pytest
from pytest_bdd import given, scenario, scenarios, then, when

from boofuzz import *

scenarios("test_s_checksum.feature")

@given("A simple boofuzz scenario works")
def simple_boofuzz_scenario(context):
    s_initialize("simple_boofuzz_scenario")
    s_static(b'\x00', name="1_static_byte")
    s_checksum("simple_boofuzz_scenario.1_static_byte")
    req = s_get("simple_boofuzz_scenario")
    output = req.render()
    pass