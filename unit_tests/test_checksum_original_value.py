from pytest_bdd import given, when, then, scenarios

from boofuzz import Checksum, Request, Block, Byte

scenarios('checksum_original_value.feature')


@given('A Checksum')
def request_one_block(context):
    request = Request("unit-test-request")
    block = Block(name="unit-test-block", request=request)
    request.push(block)
    byte1 = Byte(0x01, name="Byte block 1")
    byte2 = Byte(0x02, name="Byte block 2")
    block.push(byte1)
    block.push(byte2)
    size = Checksum(block_name="unit-test-block", request=request, fuzzable=True, name="Checksum block")
    request.push(size)
    context.uut = size
    context.block = block
    context.request = request


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


@given('Target block mutated once')
def mutate_target_block_once(context):
    context.block.mutate()


@given('Target block mutated twice')
def mutate_target_block_twice(context):
    context.block.mutate()
    context.block.mutate()


@given('Target block mutated thrice')
def mutate_target_block_thrice(context):
    context.block.mutate()
    context.block.mutate()
    context.block.mutate()


@when('Calling original_value')
def call_original_value(context):
    context.result = context.uut.original_value


@then('Result equals .render()')
def result_equals_render(context):
    assert context.result == context.uut.render()


@then('Result equals .render() after .reset()')
def result_equals_render_after_reset(context):
    context.uut.reset()
    assert context.result == context.uut.render()


@then('Result equals .render() after target block reset()')
def result_equals_render_after_reset(context):
    context.block.reset()
    assert context.result == context.uut.render()
