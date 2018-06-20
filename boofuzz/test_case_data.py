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
            msg="{title}: {index}: {name}".format(
                title=helpers.test_step_info['test_case']['title'],
                index=self.index,
                name=self.name,
            ),
            timestamp=self.timestamp,
        )
        return s

    @property
    def html_log_line(self):
        return helpers.format_log_msg(
            msg_type='test_case',
            msg=helpers.test_step_info['test_case']['html_format'].format(
                msg='{index}: {name}'.format(index=self.index, name=self.name),
            ),
            timestamp=self.timestamp,
        )

    @property
    def css_class(self):
        return helpers.test_step_info['test_case']['css_class']
