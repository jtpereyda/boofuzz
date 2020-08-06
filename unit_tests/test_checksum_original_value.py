import struct

from pytest_bdd import given, parsers, scenarios, then, when

from boofuzz import Block, Byte, Checksum, DWord, QWord, Request

scenarios("checksum_original_value.feature")


@given("A Checksum")
def a_checksum(context):
    request = Request("unit-test-request")

    block = Block(name="unit-test-block", request=request)
    request.push(block)

    byte1 = Byte(default_value=0x01, name="Byte block 1")
    byte2 = Byte(default_value=0x02, name="Byte block 2")
    block.push(byte1)
    block.push(byte2)

    checksum = Checksum(block_name="unit-test-block", request=request, fuzzable=True, name="Checksum block")
    request.push(checksum)

    request.pop()

    context.uut = checksum
    context.block = block
    context.request = request


@given("A UDP Checksum")
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

    checksum = Checksum(
        block_name="IPv4 Packet",
        ipv4_src_block_name="IPv4 Src Block",
        ipv4_dst_block_name="IPv4 Dst Block",
        request=request,
        fuzzable=True,
        algorithm="udp",
        name="Checksum block",
    )
    request.push(checksum)

    request.pop()

    context.uut = checksum
    context.block = ipv4_packet
    context.request = request
    context.ipv4_src = ipv4_src
    context.ipv4_dst = ipv4_dst


@when("Calling original_value")
def call_original_value(context):
    context.uut.render()  # Ensure UUT object state is updated
    context.result = context.uut.original_value


@then(parsers.parse("Render() equals 0x{value:x}"))
def result_equals_render(context, value):
    assert context.uut.render() == struct.pack(">L", value)
