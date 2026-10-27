"""Command line interface for CI pipelines.

  python -m backend.cli scan requirements.txt package-lock.json pom.xml --mode online --fail-on high
  python -m backend.cli scan . --format sarif --output results.sarif

Exit codes: 0 = OK, 1 = findings at/above --fail-on, 2 = input error or lookup unavailable.
"""
import argparse
import sys
from pathlib import Path

from backend.core.scanner import scan_many
from backend.parsers import FORMATS, detect_format
from backend.utils import report
from backend.utils.validators import validate_upload

RANK = {"UNKNOWN": 2, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
THRESH = {"none": 99, "low": 1, "medium": 2, "high": 3, "critical": 4}
FORMATTERS = {"markdown": report.to_markdown, "json": report.to_json, "sarif": report.to_sarif, "cyclonedx": report.to_cyclonedx}
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "target", "build", "__pycache__", "vendor"}


def collect(paths: list[str]) -> list[tuple[str, str]]:
    files = []
    for p in map(Path, paths):
        cands = [p] if p.is_file() else [f for f in sorted(p.rglob("*")) if f.is_file() and not (SKIP_DIRS & set(f.parts))]
        for f in cands:
            if not p.is_file():                       # directory walk: only well-known dependency file names
                low = f.name.lower()
                if low.endswith(".txt") and not (low.startswith("requirements") or low == "conanfile.txt"):
                    continue                          # e.g. CMakeLists.txt, notes.txt
                try:
                    detect_format(f.name, "")
                except ValueError:
                    continue
            try:
                files.append((str(f), validate_upload(f.name, f.read_bytes())))
            except ValueError as ex:
                if p.is_file():
                    raise
                print(f"skip {f}: {ex}", file=sys.stderr)
    return files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="dependency-detective", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("scan", help="scan manifests/lockfiles or directories")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--mode", choices=["offline", "online"], default="offline")
    sp.add_argument("--enrich", action="store_true", help="add EPSS + CISA KEV exploit signals (needs internet)")
    sp.add_argument("--fail-on", choices=list(THRESH), default="none", help="exit 1 if a finding has at least this severity")
    sp.add_argument("--format", choices=list(FORMATTERS), default="markdown")
    sp.add_argument("--output", "-o", help="write the report here instead of stdout")
    sub.add_parser("formats", help="list supported file formats")
    a = ap.parse_args(argv)
    if a.cmd == "formats":
        print("\n".join(f"{k:20} {v[0]}" for k, v in FORMATS.items()))
        return 0
    try:
        files = collect(a.paths)
        if not files:
            print("No supported dependency files found.", file=sys.stderr)
            return 2
        r = scan_many(files, a.mode, a.enrich)
    except (ValueError, OSError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    out = FORMATTERS[a.format](r)
    Path(a.output).write_text(out, encoding="utf-8") if a.output else print(out)
    s = r["summary"]
    print(f"[dependency-detective] {s['total']} packages, {s['vulnerable']} vulnerable, {s['advisories']} advisories "
          f"({s['transitive']} transitive packages seen)", file=sys.stderr)
    if s["lookup_unavailable"]:
        print("[dependency-detective] lookup unavailable: results are incomplete", file=sys.stderr)
        return 2
    worst = max((RANK.get(f["severity"], 2) for f in r["findings"]), default=0)
    return 1 if worst >= THRESH[a.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
