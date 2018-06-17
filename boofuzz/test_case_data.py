from __future__ import print_function

import sys

import attr
from . import test_step_data
from . import helpers

@attr.s
class TestCaseData(object):
    name = attr.ib()
    index = attr.ib()
    timestamp = attr.ib()
    steps = attr.ib(default={})

    @property
    def text_render(self):
        s = helpers.format_log_msg(
            type='test_case',
            msg="{title}: {index}: {name}".format(
                title=helpers.test_step_info['test_case']['title'],
                index=self.index,
                name=self.name,
            ),
            timestamp=self.timestamp,
        )
        return s
