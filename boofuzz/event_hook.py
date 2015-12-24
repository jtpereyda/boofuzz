class EventHook(object):
    """
    An EventHook that registers events using +=and -=.

    Based on spassig's solution here: http://stackoverflow.com/a/1094423/461834
    """
    def __init__(self):
        self.__handlers = []

    def __iadd__(self, handler):
        self.__handlers.append(handler)
        return self

    def __isub__(self, handler):
        self.__handlers.remove(handler)
        return self

    def __len__(self):
        return len(self.__handlers)

    def __iter__(self):
        return iter(self.__handlers)

    def fire(self, *args, **kwargs):
        """
        Call each event handler in sequence.

        @param args: Forwarded to event handler.
        @param kwargs: Forwarded to event handler.

        @return: None
        """
        for handler in self.__handlers:
            handler(*args, **kwargs)
