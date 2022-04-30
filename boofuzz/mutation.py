import attr


@attr.s
class Mutation:
    value = attr.ib(type=bytes)
    qualified_name = attr.ib(type=str)
    index = attr.ib(type=int)
