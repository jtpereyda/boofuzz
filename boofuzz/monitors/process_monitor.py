from .imonitor import IMonitor
from . import pedrpc

# Important: IMonitor needs to come *before* pedrpc.Client in the
# Inheritance list for the method resolution order to produce
# correct results.


class ProcessMonitor(IMonitor, pedrpc.Client):
    def __init__(self, host, port):
        super(IMonitor).__init__()
        super(pedrpc.Client, self).__init__(host, port)

    def alive(self):
        return super(pedrpc.Client, self).alive() # pytype: disable=attribute-error

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        return super(pedrpc.Client, self).pre_send(session.total_mutant_index) # pytype: disable=attribute-error

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return super(pedrpc.Client, self).post_send(session.total_mutant_index) # pytype: disable=attribute-error

    def retrieve_data(self):
        return b""

    def set_options(self, *args, **kwargs):
        # args will be ignored, kwargs will be translated

        for arg, value in kwargs.items():
            eval("super(pedrpc.Client, self).set_{0}(kwargs['{0}']".format(arg))

    def get_crash_synopsis(self):
        return super(pedrpc.Client, self).get_crash_synopsis() # pytype: disable=attribute-error

    def start_target(self):
        return super(pedrpc.Client, self).start_target() # pytype: disable=attribute-error

    def stop_target(self):
        return super(pedrpc.Client, self).stop_target() # pytype: disable=attribute-error

    def restart_target(self):
        return super(pedrpc.Client, self).restart_target() # pytype: disable=attribute-error
