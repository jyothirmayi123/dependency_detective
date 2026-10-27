"""C / C++: Conan (conanfile.txt, conan.lock). Conan packages are checked against the ConanCenter ecosystem in OSV.
Libraries that are vendored, installed by the OS or built from source are not visible to any manifest parser."""
import re

from backend.parsers.base import entry, load_json, set_version, unresolved

ECO = "ConanCenter"
_REF = re.compile(r"^([A-Za-z0-9_+.\-]+)/(\[[^\]]*\]|[^@#%\s]+)")


def parse_conanfile_txt(text: str) -> list[dict]:
    out, section = [], None
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section not in ("requires", "tool_requires", "build_requires"):
            continue
        m = _REF.match(line)
        e = entry(ECO, m.group(1).lower() if m else None, line=no, raw=line, direct=True,
                  scope="" if section == "requires" else "build")
        if not m:
            e.update(status="malformed", note="Line could not be parsed")
        elif m.group(2).startswith("["):
            unresolved(e, "Version range: exact version unknown (use conan.lock)", m.group(2))
        else:
            set_version(e, m.group(2))
        out.append(e)
    return out


def parse_conan_lock(text: str) -> list[dict]:
    data, refs, out = load_json(text), [], []
    refs += [("", r) for r in data.get("requires", [])] + [("build", r) for r in data.get("build_requires", [])]
    for node in ((data.get("graph_lock") or {}).get("nodes") or {}).values():  # Conan 1 lockfiles
        if node.get("ref"):
            refs.append(("", node["ref"]))
    seen = set()
    for scope, ref in refs:
        m = _REF.match(str(ref))
        if m and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            out.append(set_version(entry(ECO, m.group(1).lower(), scope=scope), m.group(2)))
    return out
