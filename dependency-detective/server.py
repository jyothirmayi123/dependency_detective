"""Web server: serves the custom frontend (web/index.html) and a JSON API over the same backend.
Run:  uvicorn server:app --reload     then open http://127.0.0.1:8000"""
import csv
import io
from pathlib import Path
import re
from tempfile import SpooledTemporaryFile
from urllib.parse import unquote, urljoin, urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel

from backend import config
from backend.core.scanner import scan_many
from backend.ecosystems import ECOSYSTEMS, label, package_download_url
from backend.utils import db, report
from backend.utils.validators import validate_text

app = FastAPI(title="Dependency Detective")
WEB = Path(__file__).parent / "web"
EXPORTS = {"markdown": (report.to_markdown, "md"), "csv": (report.to_csv, "csv"), "json": (report.to_json, "json"),
           "cyclonedx": (report.to_cyclonedx, "cdx.json"), "sarif": (report.to_sarif, "sarif"),
           "requirements": (report.to_fixed_requirements, "txt"),
           "upgrade-plan": (report.to_upgrade_plan_csv, "csv")}


class F(BaseModel):
    name: str
    text: str


class ScanReq(BaseModel):
    files: list[F]
    mode: str = "offline"
    enrich: bool = False


class UpgradeZipReq(BaseModel):
    fix_plan: list[dict]
    scanned_at: str = ""


MAX_DOWNLOADS = 100
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
ARTIFACT_EXTENSIONS = {
    "PyPI": ".tar.gz", "npm": ".tgz", "Maven": ".jar", "ConanCenter": ".tar.gz",
    "Go": ".zip", "crates.io": ".crate", "RubyGems": ".gem", "NuGet": ".nupkg",
}
REDIRECT_HOSTS = {
    "files.pythonhosted.org", "repo.maven.apache.org", "zlib.net", "www.zlib.net",
    "www.openssl.org", "openssl.org", "github.com", "release-assets.githubusercontent.com",
    "registry.npmjs.org", "proxy.golang.org", "storage.googleapis.com",
    "crates.io", "static.crates.io", "rubygems.org", "www.nuget.org",
    "globalcdn.nuget.org", "api.nuget.org",
}


def _download_response(url: str):
    for _ in range(6):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in REDIRECT_HOSTS:
            raise HTTPException(502, "Package registry redirected to an untrusted download host.")
        try:
            response = requests.get(url, stream=True, timeout=(10, 60), allow_redirects=False)
        except requests.RequestException as ex:
            raise HTTPException(502, f"Could not download package artifact: {ex}") from ex
        if response.is_redirect:
            location = response.headers.get("location")
            response.close()
            if not location:
                raise HTTPException(502, "Package registry returned a redirect without a destination.")
            url = urljoin(url, location)
            continue
        try:
            response.raise_for_status()
        except requests.RequestException as ex:
            response.close()
            raise HTTPException(502, f"Package registry download failed: {ex}") from ex
        if response.url and urlsplit(response.url).hostname not in REDIRECT_HOSTS:
            response.close()
            raise HTTPException(502, "Package registry resolved to an untrusted download host.")
        return response
    raise HTTPException(502, "Package registry redirected too many times.")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/api/demo")
def demo():
    return [{"name": f.name, "text": f.read_text(encoding="utf-8")} for f in sorted(config.SAMPLE_DIR.iterdir())
            if f.is_file() and f.name != "advisories_sample.json"]


@app.post("/api/scan")
def scan(req: ScanReq):
    if not req.files or len(req.files) > config.MAX_FILES:
        raise HTTPException(400, f"Provide 1 to {config.MAX_FILES} files.")
    if req.mode not in ("offline", "online"):
        raise HTTPException(400, "mode must be offline or online")
    try:
        files = [(f.name, validate_text(f.text)) for f in req.files]
        r = scan_many(files, req.mode, req.enrich)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    r["id"] = db.save_scan(r)
    return r


@app.get("/api/history")
def history():
    return db.list_scans()


@app.get("/api/history/{sid}")
def history_item(sid: int):
    r = db.get_scan(sid)
    if not r:
        raise HTTPException(404, "Scan not found")
    return r


@app.post("/api/export/{fmt}")
def export(fmt: str, r: dict):
    if fmt not in EXPORTS:
        raise HTTPException(404, "Unknown format")
    return PlainTextResponse(EXPORTS[fmt][0](r))


@app.post("/api/downloads/{ecosystem}")
def download_ecosystem_zip(ecosystem: str, req: UpgradeZipReq):
    if ecosystem not in ECOSYSTEMS:
        raise HTTPException(404, "Unknown package ecosystem.")
    candidates = [item for item in req.fix_plan
                  if item.get("ecosystem") == ecosystem and item.get("target")]
    if len(candidates) > MAX_DOWNLOADS:
        raise HTTPException(400, f"Too many packages to bundle (limit {MAX_DOWNLOADS}).")
    if not candidates:
        raise HTTPException(400, "There are no suggested upgrades for this language.")

    archive = SpooledTemporaryFile(max_size=10 * 1024 * 1024, mode="w+b")
    total_bytes = 0
    manifest = io.StringIO(newline="")
    writer = csv.writer(manifest)
    writer.writerow(["package", "current_version", "suggested_version", "artifact_file", "download_url"])
    try:
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zipped:
            for item in candidates:
                name, version = item.get("package"), item.get("target")
                if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
                    raise HTTPException(400, "The upgrade plan contains an invalid package or version.")
                url = package_download_url(ecosystem, name, version)
                if not url:
                    continue
                response = _download_response(url)
                safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "package"
                safe_version = re.sub(r"[^A-Za-z0-9._-]+", "_", version).strip("._") or "version"
                extension = ARTIFACT_EXTENSIONS.get(ecosystem, Path(unquote(urlsplit(url).path)).suffix or ".pkg")
                file_name = f"packages/{safe_name}-{safe_version}{extension}"
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_ARTIFACT_BYTES:
                    response.close()
                    raise HTTPException(413, f"{name} exceeds the per-package download size limit.")
                try:
                    with zipped.open(file_name, "w") as artifact:
                        for chunk in response.iter_content(chunk_size=64 * 1024):
                            if not chunk:
                                continue
                            total_bytes += len(chunk)
                            if total_bytes > MAX_ARCHIVE_BYTES:
                                raise HTTPException(413, "The language download exceeds the archive size limit.")
                            artifact.write(chunk)
                finally:
                    response.close()
                writer.writerow([name, item.get("current", ""), version, file_name, url])

            if not total_bytes:
                raise HTTPException(400, "No direct package artifacts are available for this language.")
            zipped.writestr("MANIFEST.csv", manifest.getvalue())
            zipped.writestr(
                "README.txt",
                f"Dependency Detective suggested upgrades\n"
                f"Ecosystem: {label(ecosystem)} ({ecosystem})\n"
                f"Scan timestamp: {req.scanned_at or 'not supplied'}\n\n"
                "The packages/ directory contains the exact suggested package artifacts listed in MANIFEST.csv.\n"
                "These are registry artifacts, not necessarily a complete, installable project or its transitive dependencies.\n"
                "Use the package manager and your project lockfile to install and resolve dependencies safely.\n",
            )
    except HTTPException:
        archive.close()
        raise
    except (OSError, ValueError, requests.RequestException) as ex:
        archive.close()
        raise HTTPException(502, f"Could not create the language download archive: {ex}") from ex

    archive.seek(0)
    filename = re.sub(r"[^a-z0-9]+", "-", label(ecosystem).lower()).strip("-") or "packages"
    return StreamingResponse(
        iter(lambda: archive.read(64 * 1024), b""),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}-upgrades.zip"'},
        background=BackgroundTask(archive.close),
    )
