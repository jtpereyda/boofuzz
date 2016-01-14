# pytest is required as an extras_require:
# noinspection PyPackageRequirements
import pytest


@pytest.fixture
def context():
    class Context(object):
        pass

    return Context()
