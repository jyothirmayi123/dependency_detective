"""Python: requirements.txt, poetry.lock, Pipfile.lock."""
import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from backend.parsers.base import entry, load_json, load_toml, set_version

ECO = "PyPI"


def parse_requirements(text: str) -> list[dict]:
    items, seen = [], {}
    text = re.sub(r"\\\r?\n", " ", text)  # join "\" line continuations
    for no, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()  # drop comments
        if not line:
            continue
        item = entry(ECO, raw=raw.strip(), line=no, direct=True)
        items.append(item)
        # -r, -e, --index-url, URLs and local paths are not scanned
        if line.startswith("-") or "://" in line or line.startswith((".", "/")):
            item.update(status="skipped", note="Option, URL or path: not scanned")
            continue
        line = re.sub(r"\s--hash=\S+", "", line)  # hashes are irrelevant here
        try:
            req = Requirement(line)
        except InvalidRequirement:
            item.update(status="malformed", note="Line could not be parsed")
            continue
        name = canonicalize_name(req.name)
        item.update(name=name, specifier=str(req.specifier))
        specs = list(req.specifier)
        if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
            try:
                Version(specs[0].version)
                item.update(status="exact", version=specs[0].version)
            except InvalidVersion:
                item.update(status="unresolved", note="Version is not PEP 440 valid")
        elif specs:
            item.update(status="unresolved", note="Version range: exact version unknown")
        else:
            item.update(status="unresolved", note="No version specified")
        if req.marker:
            item["note"] = (item["note"] + "; " if item["note"] else "") + "Has environment marker"
        if name in seen:
            item["duplicate_of"] = seen[name]
            item["note"] = (item["note"] + "; " if item["note"] else "") + f"Duplicate of line {seen[name]}"
        else:
            seen[name] = no
    return items


def parse_poetry_lock(text: str) -> list[dict]:
    """poetry.lock: exact versions for ALL packages plus the dependency edges (transitive analysis)."""
    out = []
    for p in load_toml(text).get("package", []):
        name = canonicalize_name(p.get("name", ""))
        if not name or not p.get("version"):
            continue
        deps = [(canonicalize_name(d), None) for d in (p.get("dependencies") or {}) if d.lower() != "python"]
        e = entry(ECO, name, deps=deps, scope="dev" if p.get("category") == "dev" else "")
        out.append(set_version(e, str(p["version"])))
    return out


def parse_pipfile_lock(text: str) -> list[dict]:
    """Pipfile.lock: pinned versions, flat list (no dependency edges)."""
    data, out = load_json(text), []
    for section, scope in (("default", ""), ("develop", "dev")):
        for name, info in (data.get(section) or {}).items():
            ver = (info.get("version") or "") if isinstance(info, dict) else ""
            e = entry(ECO, canonicalize_name(name), scope=scope)
            if ver.startswith("=="):
                out.append(set_version(e, ver[2:]))
            else:
                e.update(status="unresolved", note="No pinned version (VCS/path/editable)")
                out.append(e)
    return out
