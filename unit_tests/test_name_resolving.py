import pytest
from pytest_bdd import given, scenarios, then, when

from boofuzz import *
from boofuzz.exception import BoofuzzNameResolutionError

CONVERTERS = {
    "block_name": str,
}

scenarios("test_name_resolving.feature", example_converters=CONVERTERS)


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


@given("Complex request scenario with block <name> block_name <block_name>")
def complex_request_scenario(context, name, block_name):
    """
    my_test_request                         [default] value
    |-A                                     A1A1
    |-B1                                    B1
    |-sizer_l1 (default block_name: .A)     02
    |-C
      |-A                                   A2A2A2
      |-B2                                  B2
      |-sizer_l2 (default block_name: A)    03
      |-C
        |-A                                 A3A3A3A3
        |-B3                                B3
        |-sizer_l3 (default block_name: A)  04
    """
    block_names = {
        "sizer_l1": block_name if name == "sizer_l1" else ".A",
        "sizer_l2": block_name if name == "sizer_l2" else ".A",
        "sizer_l3": block_name if name == "sizer_l3" else ".A",
    }
    s_initialize("test_req")
    s_static(b"\xA1\xA1", name="A")
    s_static(b"\xB1", name="B1")
    s_size(block_names["sizer_l1"], name="sizer_l1", length=1)
    with s_block("C"):
        s_static(b"\xA2\xA2\xA2", name="A")
        s_static(b"\xB2", name="B2")
        s_size(block_names["sizer_l2"], name="sizer_l2", length=1)
        with s_block("C"):
            s_static(b"\xA3\xA3\xA3\xA3", name="A")
            s_static(b"\xB3", name="B3")
            s_size(block_names["sizer_l3"], name="sizer_l3", length=1)

    context.req = s_get("test_req")


@when("Scenario is rendered")
def scenario_can_be_rendered(context):
    context.output = context.req.render()


@when("We try to render the scenario")
def scenario_try_render(context):
    context.exc = None
    try:
        context.output = context.req.render()
    except Exception as e:
        context.exc = e


@then("Scenario output is <result>")
def scenario_output_is(context, result):
    if result.startswith("0x"):
        result = result[2:]
    assert context.output == bytes(bytearray.fromhex(result))


@then("A BoofuzzNameResolutionError is raised")
def name_resolution_err(context):
    assert isinstance(context.exc, BoofuzzNameResolutionError)
