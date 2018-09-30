#!/usr/bin/env python
from __future__ import print_function
import logging
import time

import click
from . import constants
from . import sessions


@click.group()
def cli():
    pass


@cli.command(name='open')
@click.option('--debug', help='Print debug info to console', is_flag=True)
@click.option('--ui-port',
              help='Port on which to serve the web interface (default {0})'.format(constants.DEFAULT_PROCMON_PORT),
              type=int, default=constants.DEFAULT_WEB_UI_PORT)
@click.option('--ui-addr', help='Address on which to serve the web interface (default localhost). Set to empty '
                                'string to serve on all interfaces.', type=str, default='localhost')
@click.argument('filename')
def open_file(debug, filename, ui_port, ui_addr):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    sessions.open_test_run(db_filename=filename, port=ui_port, address=ui_addr)

    print('Serving web page at http://{0}:{1}. Hit Ctrl+C to quit.'.format(ui_addr, ui_port))
    while True:
        time.sleep(.001)


def main():
    cli()


if __name__ == "__main__":
    main()
