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
