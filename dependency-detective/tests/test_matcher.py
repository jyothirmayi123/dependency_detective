import pytest
from backend.core.matcher import find_vulns
from backend.core.remediation import recommend
from backend.core.scanner import load_sample

ADV = load_sample()["vulns"]

@pytest.mark.parametrize("name,ver,expected", [
    ("flask", "2.2.0", True), ("flask", "2.2.5", False),      # fixed boundary
    ("flask", "2.3.1", True), ("flask", "2.3.2", False),      # second range
    ("requests", "2.2.9", False), ("requests", "2.3.0", True),  # introduced boundary
    ("requests", "2.31.0", False), ("pyyaml", "5.3.1", True), ("pyyaml", "6.0", False),
    ("unknown-pkg", "1.0", False),
])
def test_ranges(name, ver, expected):
    assert bool(find_vulns(name, ver, ADV)) is expected

def test_recommendation_is_evidence_based():
    v = find_vulns("flask", "2.2.0", ADV)
    assert recommend("flask", "2.2.0", v)["version"] == "2.2.5"
    assert recommend("flask", "2.2.5", [])["version"] is None

def test_second_range_fix():
    assert recommend("flask", "2.3.0", find_vulns("flask", "2.3.0", ADV))["version"] == "2.3.2"
