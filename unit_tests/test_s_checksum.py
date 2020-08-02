from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import *
from boofuzz.mutation_context import MutationContext

scenarios("test_s_checksum.feature")


@given("Scenario can be defined")
def scenario_can_be_defined(context):
    s_initialize("simple_boofuzz_scenario")
    s_static(b"\x00", name="1_static_byte")
    s_checksum("simple_boofuzz_scenario.1_static_byte")
    context.req = s_get("simple_boofuzz_scenario")


@when("Scenario can be rendered")
def scenario_can_be_rendered(context):
    context.output = context.req.render()


@then(parsers.parse("Scenario output is 0x{value:x}"))
def scenario_output_is(context, value):
    assert context.output == value.to_bytes(5, "big")


@then("Scenario can render all mutations")
def scenario_can_be_rendered(context):
    mutations = list(context.req.get_mutations())
    for mutation in mutations:
        context.req.render(MutationContext(mutation=mutation))
