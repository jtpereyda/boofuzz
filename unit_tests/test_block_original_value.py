import struct

from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import Block, Byte, Request

scenarios("block_original_value.feature")


@given(parsers.parse("A Block with contents 0x{value:x}"))
def request_one_block(context, value):
    request = Request(name="unit-test-request")

    block = Block(name="unit-test-block", request=request)
    request.push(block)

    byte1 = Byte(default_value=value, name="Byte block 1")
    request.push(byte1)

    request.pop()

    context.uut = block


@when("Calling original_value")
def call_original_value(context):
    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value()


@then(parsers.parse("Render() equals 0x{value:x}"))
def result_equals_render(context, value):
    assert context.uut.render() == struct.pack("B", value)
