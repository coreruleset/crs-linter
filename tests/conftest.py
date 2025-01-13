import glob

import pytest
import msc_pyparser

config = """
SecRule REQUEST_COOKIES|!REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "@rx .*" "id:1,phase:2,t:none,log,deny,status:403,msg:'test'"
"""

@pytest.fixture(scope="session")
def data():
    mparser = msc_pyparser.MSCParser()
    mparser.parser.parse(config)

    return mparser.configlines


@pytest.fixture(scope="session")
def txvars():
    return {}


@pytest.fixture(scope="session")
def crs_files() -> list:
    files = glob.glob("../examples/*.conf")
    yield files
