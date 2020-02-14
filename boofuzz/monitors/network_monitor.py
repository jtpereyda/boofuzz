from .imonitor import IMonitor
import boofuzz.pedrpc as pedrpc

# Important: IMonitor needs to come *after* pedrpc.Client in the
# Inheritance list for the method resolution order to produce
# correct results.


class ProcessMonitor(IMonitor, pedrpc.Client):
    def __init__(self, host, port):
        super(pedrpc.Client, self).__init__(host, port)

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        return super(pedrpc.Client, self).pre_send(session.total_mutant_index)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        return super(pedrpc.Client, self).post_send()

    def retrieve_data(self):
        return super(pedrpc.Client, self).retrieve()

    def set_options(self, *args, **kwargs):
        # args will be ignored, kwargs will be translated

        for arg, value in kwargs.items():
            eval("super(pedrpc.Client, self).set_{0}(kwargs['{0}']".format(arg))

    def restart_target(self):
        return False  # this Monitor can't restart
