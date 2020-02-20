from .imonitor import IMonitor
from . import pedrpc

# Important: IMonitor needs to come *before* pedrpc.Client in the
# Inheritance list for the method resolution order to produce
# correct results.


class NetworkMonitor(IMonitor, pedrpc.Client):
    def __init__(self, host, port):
        super(IMonitor, self).__init__()
        super(pedrpc.Client, self).__init__(host, port)

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        return super(pedrpc.Client, self).pre_send(session.total_mutant_index)  # pytype: disable=attribute-error

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return super(pedrpc.Client, self).post_send()  # pytype: disable=attribute-error

    def retrieve_data(self):
        return super(pedrpc.Client, self).retrieve()  # pytype: disable=attribute-error

    def set_options(self, *args, **kwargs):
        # args will be ignored, kwargs will be translated

        for arg, value in kwargs.items():
            eval("super(pedrpc.Client, self).set_{0}(kwargs['{0}']".format(arg))

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        return False  # this Monitor can't restart
