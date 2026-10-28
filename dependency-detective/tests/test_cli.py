import json
from backend import config
from backend.cli import main

def test_cli_fail_on_threshold_and_formats(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.sqlite")
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.2.0\n")
    out = tmp_path / "r.sarif"
    assert main(["scan", str(req), "--format", "sarif", "-o", str(out), "--fail-on", "high"]) == 1
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert main(["scan", str(req), "--fail-on", "critical"]) == 0        # flask finding is HIGH
    assert main(["scan", str(req)]) == 0                                 # default: report only

def test_cli_clean_project_passes_and_directory_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.sqlite")
    (tmp_path / "go.mod").write_text("module m\n\ngo 1.21\n\nrequire golang.org/x/crypto v0.17.0\n")
    (tmp_path / "notes.txt.bak").write_text("ignored")
    (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text('{"dependencies":{"lodash":"4.17.15"}}')
    assert main(["scan", str(tmp_path), "--fail-on", "low"]) == 0

def test_cli_errors(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "empty-dir-does-not-exist")]) == 2
    bad = tmp_path / "package.json"; bad.write_text("{oops")
    assert main(["scan", str(bad)]) == 2

def test_cli_formats_command(capsys):
    assert main(["formats"]) == 0 and "package-lock.json" in capsys.readouterr().out

def test_cli_directory_walk_ignores_unrelated_txt(tmp_path, monkeypatch):
    from backend.cli import collect
    (tmp_path / "CMakeLists.txt").write_text("project(x)")
    (tmp_path / "requirements-dev.txt").write_text("flask==2.2.5")
    assert [n.split("/")[-1] for n, _ in collect([str(tmp_path)])] == ["requirements-dev.txt"]
