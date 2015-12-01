import sys
sys.path.insert(0, '../')

from boofuzz.primitives import String, Static, Delim


class Group(object):
    blocks = []

    def __init__(self, name, definition=None):
        self.name = name
        if definition:
            self.definition = definition

    def add_definition(self, definition):
        assert isinstance(definition, (list, tuple)), "Definition must be a list or a tuple!"
        self.definition = definition

    def render(self):
        return "".join([x.value for x in self.definition])

    def exhaust(self):
        for item in self.definition:
            while item.mutate():
                current_value = item.value
                self.log_send(current_value)
                recv_data = self.send_buffer(current_value)
                self.log_recv(recv_data)

    def __repr__(self):
        return '<%s [%s items]>' % (self.__class__.__name__, len(self.definition))

    # noinspection PyMethodMayBeStatic
    def send_buffer(self, current_value):
        return "Sent %s!" % current_value

    def log_send(self, current_value):
        pass

    def log_recv(self, recv_data):
        pass


s_static = Static
s_delim  = Delim
s_string = String

CloseHeader = Group(
    "HTTP Close Header",
    definition=[
        # GET / HTTP/1.1\r\n
        s_static("GET / HTTP/1.1\r\n"),
        # Connection: close
        s_static("Connection"), s_delim(":"), s_delim(" "), s_string("close"),
        s_static("\r\n\r\n")
    ]
)

OpenHeader = Group(
    "HTTP Open Header",
    definition=[
        # GET / HTTP/1.1\r\n
        Static("GET / HTTP/1.1\r\n"),
        # Connection: close
        Static("Connection"), Delim(":"), Delim(" "), String("open"),
        Static("\r\n\r\n")
    ]
)

# CloseHeader = Group("HTTP Close Header")
# CloseHeader.add_definition([
#     # GET / HTTP/1.1\r\n
#     s_static("GET / HTTP/1.1\r\n"),
#     # Connection: close
#     s_static("Connection"), s_delim(":"), s_delim(" "), s_string("close"),
#     s_static("\r\n\r\n")
# ])