from boofuzz import ip_constants
from boofuzz import helpers
from behave import *


@given('Empty msg')
def step_impl(context):
    context.msg = b''


@given('1 byte msg {int}')
def step_impl(context, msg):
    context.msg = msg


@given('2 bytes')
def step_impl(context):
    context.msg = b'\x00\x00'


@given('60 bytes')
def step_impl(context):
    context.msg = b'\xFF' * 60


@given('Max length - 1')
def step_impl(context):
    context.msg = b'\xFF' * (ip_constants.UDP_MAX_LENGTH - 1)


@given('Max length')
def step_impl(context):
    context.msg = b'\xFF' * ip_constants.UDP_MAX_LENGTH


@given('Max length + 1')
def step_impl(context):
    context.msg = b'\x00' * (ip_constants.UDP_MAX_LENGTH + 1)


@given('src_addr {text}')
def step_impl(context, text):
    context.src_addr = text


@given('dst_addr {text}')
def step_impl(context, text):
    context.dst_addr = text


@when('Calling udp_checksum')
def step_impl(context):
    context.result = helpers.udp_checksum(context.msg, context.src_addr, context.dst_addr)


@then('The result is {int}')
def step_impl(context, result):
    assert context.result == result
