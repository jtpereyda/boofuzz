#!/usr/bin/env python
"""Demo of Block and group functionality."""
from boofuzz import *
import boofuzz
import click


@click.command()
@click.pass_context
def groups_demo(ctx):
    cli_context = ctx.obj
    session = cli_context.session
    session._receive_data_after_each_request = False

    message1 = Request(
        "message1",
        children=(
            Simple(name="first_byte", default_value=b"\x01", fuzz_values=[b"A", b"B", b"C"]),
            Block(
                name="first_block",
                group=".first_byte",
                children=(
                    Simple(name="second_byte", default_value=b"\x02", fuzz_values=[b"1", b"2", b"3"]),
                    # Simple(name="third_byte", default_value=b"\x03", fuzz_values=[b"X", b"Y", b"Z"]),
                ),
            ),
        ),
    )

    session.connect(message1)


if __name__ == "__main__":
    boofuzz.main_helper(click_command=groups_demo)
