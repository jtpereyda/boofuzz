from pytest_bdd import given, scenarios, then, when

from boofuzz import primitives, Request

scenarios("request_original_value.feature")


@given("A Request with one block")
def request_one_block(context):
    r = Request("unit-test-request")
    r.push(primitives.Byte(default_value=0, name="byte block"))
    context.uut = r


@given("A Request with multiple blocks")
def request_multiple_blocks(context):
    r = Request("unit-test-request")
    r.push(primitives.Byte(default_value=1, name="string block"))
    r.push(primitives.String(default_value="The perfection of art is to conceal art.", name="unit-test-byte"))
    context.uut = r


@when("Calling original_value")
def call_original_value(context):
    #    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value()


@then("Result equals .render()")
def result_equals_render(context):
    assert context.result == context.uut.render()
