import struct

from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import *
from boofuzz.mutation_context import MutationContext

scenarios("test_s_checksum.feature")


@given("Scenario can be defined")
def scenario_can_be_defined(context):
    s_initialize("test_s_checksum")
    s_static(b"\x00", name="1_static_byte")
    s_checksum("1_static_byte")
    context.req = s_get("test_s_checksum")


@when("Scenario can be rendered")
def scenario_can_be_rendered(context):
    context.output = context.req.render()


@then(parsers.parse("Scenario output is 0x{value:x}"))
def scenario_output_is(context, value):
    assert context.output == struct.pack(">Q", value)[3:]


@then("Scenario can render all mutations")
def scenario_can_render_all_mutations(context):
    mutations = list(context.req.get_mutations())
    for mutation in mutations:
        context.req.render(MutationContext(mutation=mutation))
