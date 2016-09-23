from pytest_bdd import given, when, then, scenarios

from boofuzz import Request, Block, Byte

scenarios('block_original_value.feature')


@given('A Block with contents')
def request_one_block(context):
    request = Request(name="unit-test-request")

    block = Block(name="unit-test-block", request=request)
    request.push(block)

    byte1 = Byte(0x01, name="Byte block 1")
    request.push(byte1)

    request.pop()

    context.uut = block


@given('Mutated once')
def mutate_once(context):
    context.uut.mutate()


@given('Mutated twice')
def mutate_twice(context):
    context.uut.mutate()
    context.uut.mutate()


@given('Mutated thrice')
def mutate_thrice(context):
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
