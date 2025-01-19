import glob

import pytest


@pytest.fixture(scope="session")
def crsversion():
    return "OWASP_CRS/4.10.0"


@pytest.fixture(scope="session")
def txvars():
    return {}


@pytest.fixture(scope="session")
def crs_files() -> list:
    files = glob.glob("../examples/*.conf")
    yield files
