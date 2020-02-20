def apply_callback(callbacks, *args, **kwargs):
    """
    This function applies all callbacks in callbacks with the args
    in *args and **kwargs. It stops processing if a callback
    returns a value that evaluates to False.

    :param callbacks: List of functions
    :returns: None
    """

    for callback in callbacks:
        if not callback(*args, **kwargs):
            return


def apply_callback_all(callbacks, *args, **kwargs):
    """
    This function applies all callbacks in callbacs with the args
    in *args and **kwargs, regardless of their return values.
    It collects all values in a list, which is returned to the caller.

    :param callbacks: List of functions
    :returns: List
    """
    ret = []

    for callback in callbacks:
        ret.append(callback(*args, **kwargs))

    return ret
