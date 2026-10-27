"""PHP: composer.lock (exact versions + edges) and composer.json (ranges)."""
import re

from backend.parsers.base import entry, find_line, load_json, set_version, unresolved

ECO = "Packagist"


def _platform(name: str) -> bool:           # php, ext-json, lib-curl, composer-plugin-api ... (no vendor/)
    return "/" not in name


def parse_composer_lock(text: str) -> list[dict]:
    data, out = load_json(text), []
    for section, scope in (("packages", ""), ("packages-dev", "dev")):
        for p in data.get(section) or []:
            name, ver = str(p.get("name", "")).lower(), str(p.get("version", ""))
            if not name:
                continue
            deps = [(d.lower(), None) for d in (p.get("require") or {}) if not _platform(d)]
            e = entry(ECO, name, deps=deps, scope=scope)
            ver = ver[1:] if ver[:1] in "vV" else ver
            if ver.startswith("dev-") or ver.endswith("-dev"):
                unresolved(e, "Development version: exact release unknown")
            else:
                set_version(e, ver)
            out.append(e)
    return out


def parse_composer_json(text: str) -> list[dict]:
    data, out = load_json(text), []
    for section, scope in (("require", ""), ("require-dev", "dev")):
        for name, spec in (data.get(section) or {}).items():
            if _platform(name):
                continue
            e = entry(ECO, name.lower(), line=find_line(text, f'"{name}"'), specifier=str(spec), scope=scope, direct=True)
            if re.fullmatch(r"v?\d+\.\d+\.\d+", str(spec).strip()):
                set_version(e, str(spec).strip().lstrip("vV"))
            else:
                unresolved(e, "Version constraint is a range: scan composer.lock for the exact version", str(spec))
            out.append(e)
    return out
