from __future__ import division
import ast
import math
# pytest is required as an extras_require:
# noinspection PyPackageRequirements
import pytest
from pytest_bdd import parsers
from pytest_bdd import given, when, then, scenarios
from boofuzz import helpers
from boofuzz import ip_constants


scenarios('helpers_udp_checksum.feature')


@given('Empty msg')
def msg_empty(context):
    context.msg = b''


@given(parsers.cfparse('msg {msg}'))
def msg_1_byte(context, msg):
    context.msg = ast.literal_eval(msg)


@given('msg with 60 bytes')
def msg_60_bytes(context):
    # Use each bit at least once...
    all_16_bits = b'\x00\x01\x00\x02\x00\x04\x00\x08\x00\x10\x00\x20\x00\x40\x00\x80' + \
                  b'\x01\x00\x02\x00\x04\x00\x08\x00\x10\x00\x20\x00\x40\x00\x80\x00'
    # Then fill the remaining bytes.
    # Note that using all FF bytes causes a boring pattern, since FFFF + FFFF
    # with carry is just FFFF again. 0x8001 adds just a little bit at a time,
    # hopefully ensuring that all bytes are actually factored into the answer.
    filler = b'\x80\x01' * ((60 - len(all_16_bits)) // 2)
    context.msg = all_16_bits + filler

    assert len(context.msg) == 60


@given('Maximum length - 1 msg')
def msg_max_minus_1(context):
    context.msg = b'\x80\x01' * int(math.ceil(ip_constants.UDP_MAX_LENGTH_THEORETICAL / 2))
    context.msg = context.msg[0:ip_constants.UDP_MAX_LENGTH_THEORETICAL - 1]
    assert len(context.msg) == ip_constants.UDP_MAX_LENGTH_THEORETICAL - 1


@given('Maximum length msg')
def msg_max(context):
    context.msg = b'\x80\x01' * int(math.ceil(ip_constants.UDP_MAX_LENGTH_THEORETICAL / 2))
    context.msg = context.msg[0:ip_constants.UDP_MAX_LENGTH_THEORETICAL]
    assert len(context.msg) == ip_constants.UDP_MAX_LENGTH_THEORETICAL


@given('Maximum length + 1 msg')
def msg_max_plus_1(context):
    context.msg = b'\x80\x01' * int(math.ceil((ip_constants.UDP_MAX_LENGTH_THEORETICAL + 1) / 2))
    context.msg = context.msg[0:ip_constants.UDP_MAX_LENGTH_THEORETICAL + 1]
    assert len(context.msg) == ip_constants.UDP_MAX_LENGTH_THEORETICAL + 1


@given(parsers.cfparse('src_addr {text}'))
def src_addr(context, text):
    context.src_addr = helpers.ip_str_to_bytes(text)


@given(parsers.cfparse('dst_addr {text}'))
def dst_addr(context, text):
    context.dst_addr = helpers.ip_str_to_bytes(text)


@when('Calling udp_checksum')
def call_udp_checksum(context):
    context.result = helpers.udp_checksum(context.msg, context.src_addr, context.dst_addr)


@then(parsers.cfparse('The result is {result:d}'))
def result_is(context, result):
    assert context.result == result


if __name__ == '__main__':
    pytest.main()
