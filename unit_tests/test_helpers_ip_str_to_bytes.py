# pytest is required as an extras_require:
# noinspection PyPackageRequirements
import pytest
from pytest_bdd import given, when, then, scenarios, scenario
from boofuzz import helpers


@pytest.mark.parametrize(['ip_str', 'ip_bytes'],
                         [('127.0.0.1', b'\x7F\x00\x00\x01'),
                          ('255.255.255.255', b'\xFF\xFF\xFF\xFF'),
                          ('0.0.0.0', b'\x00\x00\x00\x00'),
                          ('0.1.2.3', b'\x00\x01\x02\x03'),
                          ('1.2.3', b'\x01\x02\x00\x03'),
                          ('1.2.256', b'\x01\x02\x01\x00'),
                          ('1.2.65535', b'\x01\x02\xFF\xFF'),
                          ('1.16777215', b'\x01\xFF\xFF\xFF'),
                          ('4294967294', b'\xFF\xFF\xFF\xFE')])
@scenario('helpers_ip_str_to_bytes.feature', 'Valid IP addresses')
def test_valid_ip_addresses(ip_str, ip_bytes):
    pass


@pytest.mark.parametrize('bad_ip_str',
                         ['256.0.0.0',
                          '0.256.0.0',
                          '0.0.256.0',
                          '0.0.0.256',
                          '1.2.3.',
                          '1.2.3.-1',
                          '1.2..3',
                          '1..2.3',
                          '.1.2.3',
                          ''])
@scenario('helpers_ip_str_to_bytes.feature', 'Invalid IP addresses')
def test_invalid_ip_addresses(bad_ip_str):
    _ = bad_ip_str
    pass


scenarios('helpers_ip_str_to_bytes.feature')


@given("Various IP addresses and expected values")
def ips_and_values(context, ip_str, ip_bytes):
    context.ip = ip_str
    context.expected = ip_bytes


@when("Calling ip_str_to_bytes")
def call(context):
    try:
        context.result = helpers.ip_str_to_bytes(context.ip)
    except ValueError as e:
        context.exc_info = e


@then("The result is as expected")
def result_as_expected(context):
    assert context.result == context.expected


@given("Various invalid IP addresses")
def invalid_ips(context, bad_ip_str):
    context.ip = bad_ip_str


@then("A ValueError exception is raised")
def except_raised(context):
    assert isinstance(context.exc_info, ValueError)
