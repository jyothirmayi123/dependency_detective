import pytest
from backend import config
from backend.core.compare import diff_reports
from backend.core.scanner import scan
from backend.services import osv_service
from backend.utils.report import to_csv, to_json, to_markdown
from backend.utils.validators import validate_text, validate_upload

@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.sqlite")

SAMPLE = config.SAMPLE_REQUIREMENTS.read_text()

def test_offline_scan_sample():
    r = scan(SAMPLE, "offline")
    s = r["summary"]
    assert s["vulnerable"] >= 7 and s["no_match"] == 1 and s["unresolved"] == 2
    assert s["malformed"] == 1 and s["skipped"] == 1 and r["findings"]

def test_online_failure_is_reported_not_crash(monkeypatch):
    def boom(_): raise ConnectionError("no network")
    monkeypatch.setattr(osv_service, "query_batch", boom)
    r = scan("flask==2.2.0", "online")
    assert r["packages"][0]["status"] == "lookup_unavailable" and r["warnings"]

def test_exports_and_compare():
    a, b = scan("flask==2.2.0", "offline"), scan("flask==2.2.5", "offline")
    assert "flask" in to_csv(a) and "Incomplete checks" in to_markdown(a) and '"findings"' in to_json(a)
    d = diff_reports(a, b)
    assert d["resolved"] and not d["new"]

@pytest.mark.parametrize("name,data", [("a.txt", b""), ("a.pdf", b"x"), ("a.txt", b"x" * (3 * 1024 * 1024)), ("a.txt", b"\xff\xfe\x00")])
def test_invalid_uploads(name, data):
    with pytest.raises(ValueError):
        validate_upload(name, data)

def test_empty_text():
    with pytest.raises(ValueError):
        validate_text("   \n")
