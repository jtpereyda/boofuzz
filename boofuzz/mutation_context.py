import attr


@attr.s
class MutationContext(object):
    mutation = attr.ib()
