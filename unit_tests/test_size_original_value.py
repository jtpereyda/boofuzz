import struct

from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import BasePrimitive, Block, Byte, Request, Size

scenarios("size_original_value.feature")


class SizeChangingBlock(BasePrimitive):
    def __init__(self, value=b"\x01", name=None):
        """A block that changes size with each mutation."""
        super(SizeChangingBlock, self).__init__()

        self._name = name
        self._value = self._original_value = value

        self._fuzz_library.append(b"\x01\x02")
        self._fuzz_library.append(b"\x01\x02" * 1000)
        self._fuzz_library.append(b"\x01\x02" * 5)


@given("A Size")
def request_one_block(context):
    request = Request("unit-test-request")

    block = Block(name="unit-test-block", request=Request)
    request.push(block)

    byte1 = Byte(default_value=0x01, name="Byte block 1")
    byte2 = Byte(default_value=0x02, name="Byte block 2")
    request.push(byte1)
    request.push(byte2)

    request.pop()

    size = Size(block_name="unit-test-block", request=request, fuzzable=True, name="Size block")
    request.push(size)

    context.uut = size


@when("Calling original_value")
def call_original_value(context):
    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value()


@then(parsers.parse("Render() equals 0x{value:x}"))
def result_equals_render(context, value):
    assert context.uut.render() == struct.pack(">L", value)
