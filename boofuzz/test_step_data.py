from __future__ import print_function

import attr
import sys

from . import helpers

@attr.s
class TestStepData(object):
    type = attr.ib()
    description = attr.ib()
    data = attr.ib()
    timestamp = attr.ib()

    @property
    def text_render(self):
        if self.description is not None and self.description != '':
            msg = self.description
        elif self.data is not None and len(self.data) > 0:
            msg = helpers.hex_to_hexstr(input_bytes=self.data)
        else:
            msg = ''

        return helpers.format_log_msg(
            type=self.type,
            msg="{title}: {msg}".format(
                title=helpers.test_step_info[self.type]['title'],
                msg=msg,
            ),
            timestamp=self.timestamp,
        )
