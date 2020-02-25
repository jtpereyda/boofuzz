import pytest


@pytest.fixture
def context():
    class Context(object):
        pass

    return Context()
