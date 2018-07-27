from pytest_bdd import given, when, then, scenarios, parsers

from boofuzz import BitField

scenarios('bit_field_original_value.feature')


@given('A BitField')
def request_one_block(context):
    context.uut = BitField(100, width=8)


@given('A 4 byte BitField with value 100')
def bitfield_ascii_100(context):
    context.uut = BitField(100, width=32)


@given(parsers.parse('A 4 byte BitField with value {value:d} and format ascii'))
def bitfield_4_bytes(context, value):
    context.uut = BitField(value, width=32, output_format='ascii')


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
    context.result = context.uut.original_value


@when('Calling render')
def call_render(context):
    context.result = context.uut.render()


@then('Result equals .render()')
def result_equals_render(context):
    assert context.result == context.uut.render()


@then('Result equals .render() after .reset()')
def result_equals_render_after_reset(context):
    context.uut.reset()
    assert context.result == context.uut.render()


@then(parsers.parse('len(result) == {size:d}'))
def len_result_equals(context, size):
    assert len(context.result) == size


@then(parsers.parse('len(uut) == {size:d}'))
def len_uut_equals(context, size):
    assert len(context.uut) == size
