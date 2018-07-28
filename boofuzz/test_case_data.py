from __future__ import print_function

import attr

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
            msg_type='test_case',
            description=self.description,
            timestamp=self.timestamp,
            format_type='terminal',
        )
        return s

    @property
    def html_log_line(self):
        return helpers.format_log_msg(
            msg_type='test_case',
            description=self.description,
            timestamp=self.timestamp,
            format_type='html',
        )

    @property
    def description(self):
        return "{index}: {name}".format(
                index=self.index,
                name=self.name,
            )

    @property
    def css_class(self):
        return helpers.test_step_info['test_case']['css_class']
