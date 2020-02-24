from .imonitor import IMonitor
from . import pedrpc

# Important: IMonitor needs to come *before* pedrpc.Client in the
# Inheritance list for the method resolution order to produce
# correct results.


class NetworkMonitor(IMonitor, pedrpc.Client):
    """
    Proxy class for the network monitor interface.

    In Versions < 0.2.0, boofuzz had network and process monitors
    that communicated over RPC. The RPC client was directly passed
    to the session class, and resolved all method calls dynamically
    on the RPC partner.

    Since 0.2.0, every monitor class must implement the abstract class
    IMonitor, which defines a common interface among all Monitors. To
    aid future typehinting efforts and to make Network- and Process Monitors
    disambiguable, this explicit proxy class has been introduced that
    fast-forwards all calls to the RPC partner.

    .. versionadded:: 0.2.0
    """

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
        """
        The old RPC interfaces specified set_foobar methods to set options.
        As these vary by RPC implementation, this trampoline method translates
        arguments that have been passed as keyword arguments to set_foobar calls.

        If you call ``set_options(foobar="barbaz")``, it will result in a call to
        ``set_foobar("barbaz")`` on the RPC partner.
        """
        # args will be ignored, kwargs will be translated

        for arg, value in kwargs.items():
            eval("super(pedrpc.Client, self).set_{0}(kwargs['{0}']".format(arg))

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        return False  # this Monitor can't restart
