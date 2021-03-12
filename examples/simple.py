#!/usr/bin/env python
"""Demo of a very simple protocol definition using the Simple primitive."""
from boofuzz import *
import boofuzz
import click


@click.command()
@click.pass_context
def simple(ctx):
    cli_context = ctx.obj
    session = cli_context.session
    session._receive_data_after_each_request = False

    message1 = Request(
        "message1",
        children=(
            Simple(name="first_byte", default_value=b"\x01", fuzz_values=[b"A", b"B", b"C"]),
            Simple(name="second_byte", default_value=b"\x02", fuzz_values=[b"1", b"2", b"3"]),
            Simple(name="third_byte", default_value=b"\x03", fuzz_values=[b"X", b"Y", b"Z"]),
        ),
    )

    message2 = Request(
        "message2",
        children=(
            Simple(name="first_byte", default_value=b"\x01", fuzz_values=[b"A", b"B", b"C"]),
            Simple(name="second_byte", default_value=b"\x02", fuzz_values=[b"1", b"2", b"3"]),
        ),
    )

    session.connect(message1)
    session.connect(message1, message2)


if __name__ == "__main__":
    boofuzz.main_helper(click_command=simple)
