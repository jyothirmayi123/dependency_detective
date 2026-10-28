from backend.core.parser import parse_requirements

def by_status(items, s): return [i for i in items if i["status"] == s]

def test_exact_pin_and_comment():
    i = parse_requirements("Flask==2.2.0  # web")[0]
    assert (i["name"], i["version"], i["status"]) == ("flask", "2.2.0", "exact")

def test_name_normalization():
    assert parse_requirements("Typing_Extensions==4.0.0")[0]["name"] == "typing-extensions"

def test_ranges_and_unpinned_are_unresolved():
    items = parse_requirements("numpy>=1.24\npandas\nrequests==2.*")
    assert len(by_status(items, "unresolved")) == 3

def test_malformed_and_options():
    items = parse_requirements("not valid !!\n-r other.txt\n--index-url https://x.y")
    assert len(by_status(items, "malformed")) == 1 and len(by_status(items, "skipped")) == 2

def test_duplicates_flagged():
    items = parse_requirements("flask==2.2.0\nFlask==2.3.0")
    assert items[1]["duplicate_of"] == 1

def test_hash_and_continuation():
    assert parse_requirements("flask==2.2.0 \\\n  --hash=sha256:abc")[0]["status"] == "exact"
