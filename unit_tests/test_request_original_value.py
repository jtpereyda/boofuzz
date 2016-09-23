from pytest_bdd import given, when, then, scenarios

from boofuzz import Request
from boofuzz import primitives

scenarios('request_original_value.feature')


@given('A Request with one block')
def request_one_block(context):
    r = Request("unit-test-request")
    r.push(primitives.Byte(value=0, name="byte block"))
    context.uut = r


@given('A Request with multiple blocks')
def request_multiple_blocks(context):
    r = Request("unit-test-request")
    r.push(primitives.Byte(value=1, name="string block"))
    r.push(primitives.String(value="The perfection of art is to conceal art.", name="unit-test-byte"))
    context.uut = r


@given('Request is mutated once')
def mutate_once(context):
    context.uut.mutate()


@given('Request is mutated twice')
def mutate_twice(context):
    context.uut.mutate()
    context.uut.mutate()


@given('Request is mutated thrice')
def mutate_twice(context):
    context.uut.mutate()
    context.uut.mutate()
    context.uut.mutate()


@when('Calling original_value')
def call_original_value(context):
    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value


@then('Result equals .render()')
def result_equals_render(context):
    assert context.result == context.uut.render()


@then('Result equals .render() after .reset()')
def result_equals_render_after_reset(context):
    context.uut.reset()
    assert context.result == context.uut.render()
