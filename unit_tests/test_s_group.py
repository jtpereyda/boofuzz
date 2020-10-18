import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import *
from boofuzz.mutation_context import MutationContext

scenarios("test_s_group.feature")


@pytest.fixture(autouse=True)
def clear_requests():
    yield
    blocks.REQUESTS = {}
    blocks.CURRENT = None


@given("Scenario with str can be defined")
def scenario_with_str_can_be_defined(context):
    s_initialize("test_s_group_str")
    s_group("1_group_str", values=["\x06"], default_value="\x06")
    context.req = s_get("test_s_group_str")


@given("Scenario with byte can be defined")
def scenario_with_byte_can_be_defined(context):
    s_initialize("test_s_group_byte")
    s_group("1_group_byte", values=[b"\x06"], default_value=b"\x06")
    context.req = s_get("test_s_group_byte")


@given("Groups and blocks scenario")
def scenario_groups_blocks(context):
    s_initialize("test_groups_blocks_mutations")
    s_group("group1", values=["\x01", "\x02", "\x03"], default_value="\x01")
    with s_block("block1", group=".group1"):
        s_group("group2", values=["\x11", "\x12", "\x13", "\x14"], default_value="\x11")

    context.req = s_get("test_groups_blocks_mutations")


@when("Scenario can be rendered")
def scenario_can_be_rendered(context):
    context.output = context.req.render()
    context.mutations = list(context.req.get_mutations())


@then(parsers.parse("Scenario output is 0x{value}"))
def scenario_output_is(context, value):
    assert context.output == bytes(bytearray.fromhex(value))


@then("Output of mutation <mutation> is <result>")
def scenario_output_as(context, mutation, result):
    if result.startswith("0x"):
        result = result[2:]
        result = bytes(bytearray.fromhex(result))
    mutation = int(mutation)
    assert context.req.render(MutationContext(mutation=context.mutations[mutation])) == result


@then("All mutations render")
def scenario_can_render_all_mutations(context):
    for mutation in context.mutations:
        context.req.render(MutationContext(mutation=mutation))


@then(parsers.parse("There are {value:d} total mutations"))
def total_mutations(context, value):
    assert len(context.mutations) == value
