import struct
import pytest

from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import *
from boofuzz.mutation_context import MutationContext

CONVERTERS = {
    "block_name": str,
}

scenarios("test_name_resolving.feature", example_converters=CONVERTERS)


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


@given("A flat scenario with block_name <block_name>")
def a_flat_scenario(context, block_name):
    s_initialize("test_name_resolving")
    s_static(b"\xff\xff", name="2_static_bytes")
    s_size(block_name, length=1)
    s_static(b"\xff", name="1_static_byte")
    context.req = s_get("test_name_resolving")


@given("A 1 deep scenario with block_name <block_name>")
def a_1_deep_scenario(context, block_name):
    s_initialize("test_name_resolving")
    s_static(b"\xff", name="header")
    s_size(block_name, length=1)
    with s_block("1_deep"):
        s_static(b"\xfe", name="1_static_byte")
    s_static(b"\xff", name="1_static_byte")
    context.req = s_get("test_name_resolving")


@given("A 1 deep higher scenario with block_name <block_name>")
def a_1_deep_higher_scenario(context, block_name):
    s_initialize("test_name_resolving")
    s_static(b"\xff", name="header")
    with s_block("1_deep"):
        s_size(block_name, length=1)
        s_static(b"\xfe", name="1_byte_inside")
    s_static(b"\xff", name="1_byte_root")
    context.req = s_get("test_name_resolving")


@when("Scenario can be rendered")
def scenario_can_be_rendered(context):
    context.output = context.req.render()


@then(parsers.parse("Scenario output is 0x{value:x}"))
def scenario_output_is(context, value):
    assert context.output == struct.pack(">L", value)


@then("Scenario can render all mutations")
def scenario_can_render_all_mutations(context):
    mutations = list(context.req.get_mutations())
    for mutation in mutations:
        context.req.render(MutationContext(mutation=mutation))
