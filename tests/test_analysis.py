import json
import pytest
from backend import config
from backend.core import graph, risk, typosquat
from backend.core.matcher import AdvisoryIndex
from backend.core.scanner import load_sample, scan, scan_many
from backend.ecosystems import package_download_url, purl
from backend.services import enrichment, osv_service
from backend.utils import report

@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.sqlite")

ADV = AdvisoryIndex(load_sample()["vulns"])

@pytest.mark.parametrize("eco,name,ver,hit", [
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", True), ("Maven", "org.apache.logging.log4j:log4j-core", "2.15.0", False),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.0-beta9", True), ("Maven", "org.apache.logging.log4j:log4j-core", "2.3.1", False),
    ("npm", "minimist", "0.0.8", True), ("npm", "minimist", "1.2.5", True), ("npm", "minimist", "1.2.6", False), ("npm", "minimist", "0.2.4", False),
    ("ConanCenter", "openssl", "1.1.1m", True), ("ConanCenter", "openssl", "1.1.1n", False), ("ConanCenter", "openssl", "1.0.2", False),
    ("Go", "golang.org/x/crypto", "0.16.0", True), ("Go", "golang.org/x/crypto", "0.17.0", False),
    ("PyPI", "flask", "2.2.0", True), ("npm", "flask", "2.2.0", False),   # ecosystem must match
])
def test_multi_ecosystem_matching(eco, name, ver, hit):
    assert bool(ADV.find(eco, name, ver)) is hit

# ---- CVSS + risk -------------------------------------------------------------------------
@pytest.mark.parametrize("vec,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1), ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_scores(vec, score):
    assert risk.cvss3_score(vec) == score

def test_cvss_rejects_garbage_and_v4():
    assert risk.cvss3_score("nonsense") is None and risk.cvss3_score("CVSS:4.0/AV:N/AC:L") is None

def test_severity_prefers_source_label_else_computes():
    assert risk.severity_info({"database_specific": {"severity": "MODERATE"}})["label"] == "MEDIUM"
    s = risk.severity_info({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]})
    assert (s["label"], s["score"]) == ("CRITICAL", 9.8)
    assert risk.severity_info({})["label"] == "UNKNOWN"

def test_priority_orders_by_exploit_evidence_and_exposure():
    base = risk.priority("HIGH", 7.5, None, False, False, 0)["score"]
    assert risk.priority("HIGH", 7.5, None, True, False, 0)["score"] > risk.priority("HIGH", 7.5, 0.5, False, False, 0)["score"] > base
    assert risk.priority("HIGH", 7.5, None, False, True, 0)["score"] > base
    assert 0 <= risk.priority("CRITICAL", 10, 1, True, True, 99)["score"] <= 100

# ---- graph --------------------------------------------------------------------------------
LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"mkdirp": "0.5.1"}},
    "node_modules/mkdirp": {"version": "0.5.1", "dependencies": {"minimist": "0.0.8"}},
    "node_modules/minimist": {"version": "0.0.8"}}})

def test_transitive_finding_has_path_and_fix_plan():
    r = scan(LOCK, "offline", "package-lock.json")
    f = r["findings"][0]
    assert (f["package"], f["direct"], f["via"]) == ("minimist", False, ["mkdirp@0.5.1", "minimist@0.0.8"])
    plan = r["fix_plan"][0]
    assert plan["target"] == "0.2.4" and "mkdirp" in plan["action"] and "overrides" in plan["command"]
    assert r["summary"]["transitive"] == 1

def test_direct_inferred_for_lockfiles_without_roots():
    poetry = '[[package]]\nname = "flask"\nversion = "2.2.0"\n[package.dependencies]\nwerkzeug = "*"\n[[package]]\nname = "werkzeug"\nversion = "2.2.3"\n[metadata]\ncontent-hash = "x"\n'
    p = {x["package"]: x for x in scan(poetry, "offline", "poetry.lock")["packages"]}
    assert p["flask"]["direct"] is True and p["werkzeug"]["direct"] is False

def test_layered_layout_keeps_only_vulnerable_chains():
    gd = scan(LOCK + " ", "offline", "package-lock.json")["graph"]
    lay = graph.layered_layout(gd, only_vulnerable=True)
    assert len(lay["nodes"]) == 2 and len(lay["edges"]) == 1
    assert {pos[0] for pos in lay["pos"].values()} == {1, 2}

# ---- typosquat ----------------------------------------------------------------------------
@pytest.mark.parametrize("eco,name,expected", [
    ("npm", "expresss", "express"), ("PyPI", "reqeusts", "requests"), ("PyPI", "requests", None),
    ("npm", "lodash", None), ("npm", "@scope/lodahs", None), ("Maven", "g:expresss", None), ("PyPI", "abc", None),
])
def test_typosquat(eco, name, expected):
    hit = typosquat.check(eco, name)
    assert (hit["similar_to"] if hit else None) == expected

# ---- multi-file scan ------------------------------------------------------------------------
def test_multi_file_scan_all_languages():
    files = [(f.name, f.read_text()) for f in sorted(config.SAMPLE_DIR.iterdir()) if f.name != "advisories_sample.json"]
    r = scan_many(files)
    eco = r["summary"]["by_ecosystem"]
    assert set(eco) == {"PyPI", "npm", "Maven", "ConanCenter", "Go", "crates.io", "RubyGems", "NuGet"}
    assert all(eco[e]["vulnerable"] >= 1 for e in eco if e != "NuGet")
    assert r["signals"] and r["signals"][0]["package"] == "expresss"
    assert [x["max_risk"] for x in r["fix_plan"]] == sorted((x["max_risk"] for x in r["fix_plan"]), reverse=True)

def test_bad_file_error_names_file():
    with pytest.raises(ValueError, match="broken.json"):
        scan_many([("broken.json", '{"lockfileVersion": 3, "packages": ')])

# ---- exports --------------------------------------------------------------------------------
@pytest.fixture
def multi():
    return scan_many([(f.name, f.read_text()) for f in sorted(config.SAMPLE_DIR.iterdir()) if f.name in ("pom.xml", "package-lock.json", "requirements.txt")])

def test_sarif_shape(multi):
    d = json.loads(report.to_sarif(multi))
    assert d["version"] == "2.1.0" and d["runs"][0]["results"]
    res = d["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert {r["id"] for r in d["runs"][0]["tool"]["driver"]["rules"]} >= {res["ruleId"]}

def test_cyclonedx_shape(multi):
    d = json.loads(report.to_cyclonedx(multi))
    refs = {c["bom-ref"] for c in d["components"]}
    assert d["bomFormat"] == "CycloneDX" and d["specVersion"] == "1.5" and "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in refs
    assert all(a["ref"] in refs for v in d["vulnerabilities"] for a in v["affects"])
    assert any(dep["ref"].startswith("pkg:npm/mkdirp") for dep in d["dependencies"])

def test_purl():
    assert purl("npm", "@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert purl("Maven", "g:a", "1.0") == "pkg:maven/g/a@1.0" and purl("Go", "golang.org/x/net", "0.1.0") == "pkg:golang/golang.org/x/net@0.1.0"

def test_suggested_package_download_urls():
    assert package_download_url("crates.io", "regex", "1.5.5") == \
        "https://crates.io/api/v1/crates/regex/1.5.5/download"
    assert package_download_url("npm", "@scope/pkg", "1.2.3") == \
        "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"
    assert package_download_url("Maven", "org.example:library", "2.0") == \
        "https://repo.maven.apache.org/maven2/org/example/library/2.0/library-2.0.jar"
    assert package_download_url("Go", "golang.org/x/net", "0.17.0") == \
        "https://proxy.golang.org/golang.org/x/net/@v/v0.17.0.zip"
    assert package_download_url("ConanCenter", "zlib", "1.2.13") == \
        "https://zlib.net/fossils/zlib-1.2.13.tar.gz"
    assert package_download_url("ConanCenter", "openssl", "1.1.1n") == \
        "https://www.openssl.org/source/old/1.1.1/openssl-1.1.1n.tar.gz"
    assert package_download_url("PyPI", "PyYAML", "5.4") == \
        "https://files.pythonhosted.org/packages/b5/fd/15638de2da0a5aa91c095718444624aa565f766fc178249ca6faa372f71a/PyYAML-5.4.tar.gz"
    assert package_download_url("PyPI", "FLASK", "2.2.5") == \
        "https://files.pythonhosted.org/packages/5f/76/a4d2c4436dda4b0a12c71e075c508ea7988a1066b06a575f6afe4fecc023/Flask-2.2.5.tar.gz"
    assert package_download_url("PyPI", "unknown", "1.0") is None

def test_fixed_requirements_and_markdown(multi):
    fixed = report.to_fixed_requirements(multi)
    assert "flask==2.2.5" in fixed and "lodash" not in fixed
    md = report.to_markdown(multi)
    assert "Fix plan" in md and "Introduced via" in md and "By language" in md

def test_upgrade_plan_csv_includes_cross_ecosystem_suggestions():
    csv = report.to_upgrade_plan_csv({"fix_plan": [{
        "ecosystem": "crates.io", "package": "regex", "current": "1.5.4", "target": "1.5.5",
        "direct": True, "file": "Cargo.lock", "advisories": ["GHSA-m5pq-gvj9-9vr8"],
        "max_risk": 57, "command": "cargo update regex",
        "upgrade_url": "https://crates.io/api/v1/crates/regex/1.5.5/download",
    }]})
    assert "ecosystem,package,current,suggested" in csv
    assert "regex" in csv and "1.5.4" in csv and "1.5.5" in csv
    assert "https://crates.io/api/v1/crates/regex/1.5.5/download" in csv

# ---- online paths (network mocked) ------------------------------------------------------------
class Resp:
    def __init__(self, data): self.data = data
    def raise_for_status(self): pass
    def json(self): return self.data

def test_osv_pagination_follows_next_page_token(monkeypatch):
    calls = []
    def post(url, json, timeout):
        calls.append(json)
        if "page_token" not in json["queries"][0]:
            return Resp({"results": [{"vulns": [{"id": "A"}], "next_page_token": "t1"}]})
        return Resp({"results": [{"vulns": [{"id": "B"}]}]})
    monkeypatch.setattr(osv_service.requests, "post", post)
    assert osv_service.query_batch([("npm", "x", "1.0.0")]) == [["A", "B"]] and len(calls) == 2
    assert calls[0]["queries"][0]["package"] == {"name": "x", "ecosystem": "npm"}

def test_online_scan_uses_ecosystem_and_skips_withdrawn(monkeypatch):
    vuln = {"id": "GHSA-x", "summary": "s", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
    gone = {**vuln, "id": "GHSA-gone", "withdrawn": "2024-01-01T00:00:00Z"}
    seen = {}
    def qb(pairs): seen["pairs"] = pairs; return [["GHSA-x", "GHSA-gone"]]
    monkeypatch.setattr(osv_service, "query_batch", qb)
    monkeypatch.setattr(osv_service, "get_vulns", lambda ids: {"GHSA-x": vuln, "GHSA-gone": gone})
    r = scan('{"dependencies": {"lodash": "4.17.15"}}', "online", "package.json")
    assert seen["pairs"] == [("npm", "lodash", "4.17.15")] and [f["id"] for f in r["findings"]] == ["GHSA-x"]
    assert r["findings"][0]["fixed_in"] == ["4.17.21"]

def test_enrichment_raises_priority_and_failure_is_a_warning(monkeypatch):
    base = scan(LOCK, "offline", "package-lock.json")
    monkeypatch.setattr(enrichment, "fetch_kev", lambda: {"CVE-2021-44906"})
    monkeypatch.setattr(enrichment, "fetch_epss", lambda cves: {"CVE-2021-44906": 0.9})
    hot = scan(LOCK, "offline", "package-lock.json", enrich=True)
    assert hot["findings"][0]["kev"] is True and hot["findings"][0]["risk"] > base["findings"][0]["risk"] + 20 and hot["enriched"]
    def boom(): raise ConnectionError("down")
    monkeypatch.setattr(enrichment, "fetch_kev", boom)
    r = scan(LOCK, "offline", "package-lock.json", enrich=True)
    assert r["warnings"] and r["findings"] and not r["enriched"]

def test_get_vulns_fetches_missing_in_parallel_and_caches(monkeypatch):
    fetched = []
    monkeypatch.setattr(osv_service, "_fetch", lambda vid: fetched.append(vid) or {"id": vid})
    assert set(osv_service.get_vulns(["A", "B", "C"])) == {"A", "B", "C"}
    osv_service.get_vulns(["A", "B"])
    assert sorted(fetched) == ["A", "B", "C"]   # second call served from cache
