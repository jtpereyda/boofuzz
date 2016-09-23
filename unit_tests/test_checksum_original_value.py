from pytest_bdd import given, when, then, scenarios

from boofuzz import Checksum, Request, Block, Byte, DWord, QWord

scenarios('checksum_original_value.feature')


@given('A Checksum')
def a_checksum(context):
    request = Request("unit-test-request")

    block = Block(name="unit-test-block", request=request)
    request.push(block)

    byte1 = Byte(0x01, name="Byte block 1")
    byte2 = Byte(0x02, name="Byte block 2")
    block.push(byte1)
    block.push(byte2)

    checksum = Checksum(block_name="unit-test-block", request=request, fuzzable=True, name="Checksum block")
    request.push(checksum)

    request.pop()

    context.uut = checksum
    context.block = block
    context.request = request


@given('A UDP Checksum')
def udp_checksum(context):
    request = Request("unit-test-request")

    block = Block(name="unit-test-block", request=request)
    request.push(block)

    ipv4_packet = QWord(0x01, name="IPv4 Packet")
    ipv4_src = DWord(0x12345678, name="IPv4 Src Block")
    ipv4_dst = DWord(0x23456789, name="IPv4 Dst Block")
    request.push(ipv4_packet)
    request.push(ipv4_src)
    request.push(ipv4_dst)

    checksum = Checksum(block_name="IPv4 Packet",
                        ipv4_src_block_name="IPv4 Src Block",
                        ipv4_dst_block_name="IPv4 Dst Block",
                        request=request,
                        fuzzable=True,
                        algorithm='udp',
                        name="Checksum block", )
    request.push(checksum)

    request.pop()

    context.uut = checksum
    context.block = ipv4_packet
    context.request = request
    context.ipv4_src = ipv4_src
    context.ipv4_dst = ipv4_dst


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


@given('ipv4_src_block_name block mutated twice')
def mutate_ipv4_src_block_twice(context):
    context.ipv4_src.mutate()
    context.ipv4_src.mutate()


@given('ipv4_dst_block_name block mutated twice')
def mutate_ipv4_dst_block_twice(context):
    context.ipv4_dst.mutate()
    context.ipv4_dst.mutate()


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


@then('Result equals .render() after target block reset()')
def result_equals_render_after_reset_target_block(context):
    context.block.reset()
    assert context.result == context.uut.render()


@then('Result equals .render() after ipv4_src_block_name reset()')
def result_equals_render_after_reset_ipv4_src(context):
    context.ipv4_src.reset()
    assert context.result == context.uut.render()


@then('Result equals .render() after ipv4_dst_block_name reset()')
def result_equals_render_after_reset_ipv4_dst(context):
    context.ipv4_dst.reset()
    assert context.result == context.uut.render()
