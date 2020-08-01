from pytest_bdd import given, scenarios, then, when

from boofuzz import Block, Byte, Request

scenarios("block_original_value.feature")


@given("A Block with contents")
def request_one_block(context):
    request = Request(name="unit-test-request")

    block = Block(name="unit-test-block", request=request)
    request.push(block)

    byte1 = Byte(default_value=0x01, name="Byte block 1")
    request.push(byte1)

    request.pop()

    context.uut = block


@when("Calling original_value")
def call_original_value(context):
    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value()


@then("Result equals .render()")
def result_equals_render(context):
    assert context.result == context.uut.render()
