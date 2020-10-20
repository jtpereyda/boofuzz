import struct

from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import BitField

scenarios("bit_field_original_value.feature")


@given("A BitField")
def request_one_block(context):
    context.uut = BitField(default_value=100, width=8, name="one_block")


@given("A 4 byte BitField with value 100")
def bitfield_ascii_100(context):
    context.uut = BitField(default_value=100, width=32, name="ascii_100")


@given(parsers.parse("A 4 byte BitField with value {value:d} and format ascii"))
def bitfield_4_bytes(context, value):
    context.uut = BitField(default_value=value, width=32, output_format="ascii", name="4_bytes")


@when("Calling original_value")
def call_original_value(context):
    context.result = struct.pack("B", context.uut.original_value())


@when("Calling render")
def call_render(context):
    context.result = context.uut.render()


@then("Result equals .render()")
def result_equals_render(context):
    assert context.result == context.uut.render()


@then(parsers.parse("len(result) == {size:d}"))
def len_result_equals(context, size):
    assert len(context.result) == size


@then(parsers.parse("len(uut) == {size:d}"))
def len_uut_equals(context, size):
    assert len(context.uut) == size
