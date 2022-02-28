import pytest


@pytest.fixture
def context():
    class Context:
        pass

    return Context()
