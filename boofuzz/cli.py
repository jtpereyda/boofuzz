#!/usr/bin/env python
from __future__ import print_function
import logging
import time

import click
from . import sessions


@click.group()
def cli():
    pass


@cli.command(name='open')
@click.option('--debug', help='Print debug info to console', is_flag=True)
@click.option('--web-app-port', help='Port on which to serve the web interface', type=int)
@click.option('--web-app-addr', help='Address on which to serve the web interface (default localhost). Set to "*" to '
                                     'serve on all interfaces.', type=str, default='localhost')
@click.argument('filename')
def open_file(debug, filename, web_app_port, web_app_addr):
    if web_app_addr == '*':
        web_app_addr = None
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    sessions.open_test_run(db_filename=filename, port=web_app_port, address=web_app_addr)

    print('Serving web page at http://{0}:{1}. Hit Ctrl+C to quit.'.format(web_app_addr, web_app_port))
    while True:
        time.sleep(.001)


def main():
    cli()


if __name__ == "__main__":
    main()
