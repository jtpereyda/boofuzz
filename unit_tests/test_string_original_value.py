from pytest_bdd import given, scenarios, then, when

from boofuzz import helpers, String

scenarios("string_original_value.feature")


@given("A String")
def request_one_block(context):
    context.uut = String(default_value="unit-test-string", name="unit-test-string")


@given("Mutated once")
def mutate_once(context):
    context.uut.mutate()


@given("Mutated twice")
def mutate_twice(context):
    context.uut.mutate()
    context.uut.mutate()


@given("Mutated thrice")
def mutate_thrice(context):
    context.uut.mutate()
    context.uut.mutate()
    context.uut.mutate()


@when("Calling original_value")
def call_original_value(context):
    context.result = helpers.str_to_bytes(context.uut.original_value())


@then("Result equals .render()")
def result_equals_render(context):
    assert context.result == context.uut.render()


@then("Result equals .render() after .reset()")
def result_equals_render_after_reset(context):
    context.uut.reset()
    assert context.result == context.uut.render()
