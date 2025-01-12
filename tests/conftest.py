import pytest

@pytest.fixture
def data():
    return "SecRule REQUEST_COOKIES|!REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* \"@rx .*\""


@pytest.fixture
def txvars():
    return "REQUEST_COOKIES|!REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/*"

