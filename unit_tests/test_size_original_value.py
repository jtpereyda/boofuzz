from pytest_bdd import given, when, then, scenarios

from boofuzz import Size, Request, Block, Byte, BasePrimitive

scenarios('size_original_value.feature')


class SizeChangingBlock(BasePrimitive):
    @property
    def name(self):
        return self._name

    def __init__(self, value=b'\x01', name=None):
        """A block that changes size with each mutation.
        """
        super(SizeChangingBlock, self).__init__()

        self._name = name
        self._value = self._original_value = value

        self._fuzz_library.append(b'\x01\x02')
        self._fuzz_library.append(b'\x01\x02'*1000)
        self._fuzz_library.append(b'\x01\x02'*5)


@given('A Size')
def request_one_block(context):
    request = Request("unit-test-request")

    block = Block(name="unit-test-block", request=Request)
    request.push(block)

    byte1 = Byte(0x01, name="Byte block 1")
    byte2 = Byte(0x02, name="Byte block 2")
    request.push(byte1)
    request.push(byte2)

    size = Size(block_name="unit-test-block", request=request, fuzzable=True, name="Size block")
    request.push(size)

    request.pop()

    context.uut = size


@given('A Size whose target block will change size upon mutation')
def request_one_block(context):
    request = Request("unit-test-request")

    block = Block(name="unit-test-block", request=Request)
    request.push(block)

    size_changing_block = SizeChangingBlock(name="size-changing-block")
    request.push(size_changing_block)

    request.pop()

    size = Size(block_name="size-changing-block", request=request, fuzzable=True, name="Size block")
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
    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value


@then('Result equals .render()')
def result_equals_render(context):
    assert context.result == context.uut.render()


@then('Result equals .render() after .reset()')
def result_equals_render_after_reset(context):
    context.uut.reset()
    assert context.result == context.uut.render()


@then('Result equals .render() after Request reset()')
def result_equals_render_after_reset(context):
    context.request.reset()
    assert context.result == context.uut.render()
