import io
import pytest
from zipfile import ZipFile
from fastapi.testclient import TestClient
from backend import config
import server
from server import app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.sqlite")
    return TestClient(app)

def test_page_and_demo(client):
    page = client.get("/").text
    assert "Dependency Detective" in page
    assert len(client.get("/api/demo").json()) >= 8

def test_scan_history_export_roundtrip(client):
    r = client.post("/api/scan", json={"files": client.get("/api/demo").json()}).json()
    assert r["summary"]["vulnerable"] >= 10 and r["id"]
    assert client.get("/api/history").json()[0]["id"] == r["id"]
    assert client.get(f"/api/history/{r['id']}").json()["summary"] == r["summary"]
    assert client.post("/api/export/sarif", json=r).json()["version"] == "2.1.0"
    assert "Fix plan" in client.post("/api/export/markdown", json=r).text

def test_errors_are_clean_400s(client):
    assert client.post("/api/scan", json={"files": []}).status_code == 400
    assert client.post("/api/scan", json={"files": [{"name": "package.json", "text": "{oops"}]}).status_code == 400
    assert client.post("/api/scan", json={"files": [{"name": "a.txt", "text": "x"}], "mode": "bogus"}).status_code == 400
    assert client.post("/api/export/nope", json={}).status_code == 404


def test_language_upgrade_zip_uses_registry_urls_and_bundles_artifacts(client, monkeypatch):
    requested = []

    class FakeResponse:
        headers = {"content-length": "8"}
        url = ""

        def __init__(self, url):
            self.url = url
            requested.append(url)

        def iter_content(self, chunk_size):
            yield b"artifact"

        def close(self):
            pass

        def raise_for_status(self):
            pass

    monkeypatch.setattr(server, "_download_response", FakeResponse)
    fix_plan = [
        {"ecosystem": "Maven", "package": "org.apache.logging.log4j:log4j-core",
         "current": "2.14.1", "target": "2.15.0", "upgrade_url": "https://evil.example/"},
        {"ecosystem": "Maven", "package": "org.springframework:spring-beans",
         "current": "5.3.10", "target": "5.3.18"},
        {"ecosystem": "npm", "package": "lodash", "current": "4.17.15", "target": "4.17.21"},
    ]
    response = client.post("/api/downloads/Maven", json={"fix_plan": fix_plan, "scanned_at": "today"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert len(requested) == 2 and all(url.startswith("https://repo.maven.apache.org/") for url in requested)
    with ZipFile(io.BytesIO(response.content)) as archive:
        artifacts = [name for name in archive.namelist() if name.startswith("packages/")]
        assert len(artifacts) == 2 and all(name.endswith(".jar") for name in artifacts)
        assert "MANIFEST.csv" in archive.namelist()
        assert "Maven" in archive.read("README.txt").decode()
