import pytest
from backend.versioning import change_type, parse_version

@pytest.mark.parametrize("eco,a,b,expected", [
    ("Maven", "2.0-beta9", "2.3.1", -1), ("Maven", "2.12.2", "2.13.0", -1), ("Maven", "5.2.20.RELEASE", "5.2.20", 0),
    ("Maven", "1.0-SNAPSHOT", "1.0", -1), ("Maven", "1.0", "1.0-sp1", -1), ("Maven", "1.0", "1.0.0", 0),
    ("ConanCenter", "1.1.1m", "1.1.1n", -1), ("ConanCenter", "1.1.1", "1.1.1m", -1),
    ("npm", "1.0.0-rc.1", "1.0.0", -1), ("npm", "1.0.0-rc.2", "1.0.0-rc.10", -1), ("npm", "1.10.0", "1.9.0", 1),
    ("Go", "0.14.0", "0.17.0", -1), ("PyPI", "2.2.5", "2.3.0", -1), ("PyPI", "1.0rc1", "1.0", -1),
])
def test_ordering(eco, a, b, expected):
    ka, kb = parse_version(eco, a), parse_version(eco, b)
    assert (ka > kb) - (ka < kb) == expected

def test_invalid_versions():
    assert parse_version("npm", "latest") is None and parse_version("PyPI", "not-a-version") is None and parse_version("Go", "") is None

def test_change_type():
    assert change_type("npm", "1.2.3", "1.2.4") == "patch" and change_type("npm", "1.2.3", "1.3.0") == "minor"
    assert change_type("Maven", "1.9", "2.0") == "major"
