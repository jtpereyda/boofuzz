import attr


@attr.s
class Mutation(object):
    mutations = attr.ib(factory=dict)
    message_path = attr.ib(factory=list)
