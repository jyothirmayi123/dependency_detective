"""Rust: Cargo.lock (exact versions + dependency tree) and Cargo.toml (ranges)."""
import re

from backend.parsers.base import entry, find_line, load_toml, set_version, skipped, unresolved

ECO = "crates.io"


def parse_cargo_lock(text: str) -> list[dict]:
    pkgs = load_toml(text).get("package", [])
    by_name = {}
    for p in pkgs:
        if str(p.get("source", "")).startswith("registry+"):
            by_name.setdefault(p["name"], []).append(p["version"])

    def resolve(dep: str):
        parts = dep.split()
        ver = parts[1] if len(parts) > 1 else (by_name.get(parts[0], [None])[0] if len(by_name.get(parts[0], [])) == 1 else None)
        return parts[0].lower(), ver

    roots = [resolve(d) for p in pkgs if not p.get("source") for d in p.get("dependencies", [])]
    out = []
    for p in pkgs:
        src = str(p.get("source", ""))
        if not src:
            continue  # the workspace's own crates
        e = entry(ECO, p["name"].lower(), deps=[resolve(d) for d in p.get("dependencies", [])])
        if not src.startswith("registry+"):
            out.append(skipped(e, "Git/path source: not a crates.io release, not scanned"))
            continue
        if roots:
            e["direct"] = any(n == e["name"] and (v is None or v == p["version"]) for n, v in roots)
        out.append(set_version(e, str(p["version"])))
    return out


def parse_cargo_toml(text: str) -> list[dict]:
    data, out = load_toml(text), []
    for section, scope in (("dependencies", ""), ("dev-dependencies", "dev"), ("build-dependencies", "build")):
        for name, val in (data.get(section) or {}).items():
            spec = val.get("version") if isinstance(val, dict) else val
            e = entry(ECO, name.lower(), line=find_line(text, name), direct=True, scope=scope, specifier=str(spec or ""))
            if isinstance(val, dict) and ("git" in val or "path" in val):
                skipped(e, "Git/path dependency: not scanned")
            elif spec and str(spec).startswith("=") and re.fullmatch(r"=\s*\d+\.\d+\.\d+\S*", str(spec)):
                set_version(e, str(spec)[1:].strip())
            else:
                unresolved(e, "Version requirement is a range: scan Cargo.lock for the exact version", str(spec or ""))
            out.append(e)
    return out
