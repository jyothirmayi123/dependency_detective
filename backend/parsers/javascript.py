"""JavaScript / Node: package.json (ranges) and package-lock.json (exact versions + dependency tree)."""
import re

from backend.parsers.base import entry, find_line, load_json, set_version, skipped, unresolved

ECO = "npm"
_EXACT = re.compile(r"^=?v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_NON_REGISTRY = re.compile(r"^(git|http|https|file|link|workspace|github|portal|patch|npm)[:+]|^[\w.-]+/[\w.-]+(#.*)?$")


def parse_package_json(text: str) -> list[dict]:
    data, out = load_json(text), []
    for section, scope in (("dependencies", ""), ("devDependencies", "dev"),
                           ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
        for name, spec in (data.get(section) or {}).items():
            e = entry(ECO, name.lower(), line=find_line(text, f'"{name}"'), specifier=str(spec), scope=scope, direct=True)
            spec = str(spec).strip()
            if _NON_REGISTRY.search(spec):
                skipped(e, "Git/URL/path/alias dependency: not scanned")
            elif _EXACT.match(spec):
                set_version(e, spec.lstrip("=v"))
            else:
                unresolved(e, "Version range: scan package-lock.json for the exact installed version", spec)
            out.append(e)
    return out


def _v1_to_packages(deps: dict, base: str = "") -> dict:
    """Convert the old lockfileVersion 1 tree into the flat 'node_modules/...' map of v2/v3."""
    flat = {}
    for name, d in (deps or {}).items():
        path = f"{base}node_modules/{name}"
        flat[path] = {"version": d.get("version"), "dev": d.get("dev"), "dependencies": d.get("requires") or {}}
        flat.update(_v1_to_packages(d.get("dependencies"), path + "/"))
    return flat


def _resolve(pk: dict, frm: str, dep: str):
    """Node's lookup rule: nested node_modules first, then walk up to the root."""
    base = frm
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in pk:
            return cand
        if not base:
            return None
        i = base.rfind("/node_modules/")
        base = base[:i] if i != -1 else ""


def parse_package_lock(text: str) -> list[dict]:
    data, out = load_json(text), []
    pk = data.get("packages")
    has_root = pk is not None and "" in pk
    if pk is None:
        pk = _v1_to_packages(data.get("dependencies"))
    root = pk.get("", {}) if has_root else {}
    root_names = set()
    for k in ("dependencies", "devDependencies", "optionalDependencies"):
        root_names |= set((root.get(k) or {}))
    for path, info in pk.items():
        if path == "" or info.get("link") or not info.get("version"):
            continue
        name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
        deps = []
        for k in ("dependencies", "optionalDependencies"):
            for d in (info.get(k) or {}):
                tgt = _resolve(pk, path, d)
                if tgt:
                    deps.append((d.lower(), pk[tgt].get("version")))
        e = entry(ECO, name.lower(), deps=deps, scope="dev" if info.get("dev") else "")
        if has_root:
            e["direct"] = path == f"node_modules/{name}" and name in root_names
        out.append(set_version(e, str(info["version"])))
    return out
