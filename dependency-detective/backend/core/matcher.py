"""Match a package version against OSV-format advisory records (any ecosystem)."""
from backend.ecosystems import normalize_name
from backend.versioning import parse_version

_ORDER = {"introduced": 0, "fixed": 1, "last_affected": 1}


def affected_entries(vuln: dict, name: str, eco: str = "PyPI"):
    """Yield the 'affected' blocks of a record that belong to this package."""
    nn = normalize_name(eco, name)
    for a in vuln.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem") == eco and normalize_name(eco, p.get("name", "")) == nn:
            yield a


def _in_range(eco: str, v, events: list) -> bool:
    evs = [(pv, k) for e in events for k, val in e.items()
           if k in _ORDER and (pv := parse_version(eco, val)) is not None]
    hit = False
    for pv, k in sorted(evs, key=lambda t: (t[0], _ORDER[t[1]])):
        if k == "introduced" and v >= pv:
            hit = True
        elif k == "fixed" and v >= pv:
            hit = False
        elif k == "last_affected" and v > pv:
            hit = False
    return hit


def version_affected(version: str, entry: dict, eco: str = "PyPI") -> bool:
    v = parse_version(eco, version)
    if v is None:
        return False
    if any(parse_version(eco, x) == v for x in entry.get("versions", [])):  # explicitly listed
        return True
    return any(_in_range(eco, v, r.get("events", [])) for r in entry.get("ranges", [])
               if r.get("type") in ("ECOSYSTEM", "SEMVER"))


def is_affected(vuln: dict, name: str, version: str, eco: str = "PyPI") -> bool:
    return any(version_affected(version, a, eco) for a in affected_entries(vuln, name, eco))


def find_vulns(name: str, version: str, advisories: list[dict], ecosystem: str = "PyPI") -> list[dict]:
    return [a for a in advisories if is_affected(a, name, version, ecosystem)]


class AdvisoryIndex:
    """Index advisories by (ecosystem, package) so a 1,000-package lockfile is not O(packages x advisories)."""

    def __init__(self, advisories: list[dict]):
        self._idx: dict = {}
        for v in advisories:
            if v.get("withdrawn"):
                continue
            for a in v.get("affected", []):
                p = a.get("package", {})
                eco = p.get("ecosystem", "")
                self._idx.setdefault((eco, normalize_name(eco, p.get("name", ""))), {})[v["id"]] = v

    def find(self, eco: str, name: str, version: str) -> list[dict]:
        cands = self._idx.get((eco, normalize_name(eco, name)), {})
        return [v for v in cands.values() if is_affected(v, name, version, eco)]


def fixes_for(vuln: dict, name: str, version: str, eco: str = "PyPI") -> list[str]:
    """Fixed versions above the current one, from ranges that contain the current version."""
    cur, out = parse_version(eco, version), []
    for a in affected_entries(vuln, name, eco):
        if version_affected(version, a, eco):
            for r in a.get("ranges", []):
                for e in r.get("events", []):
                    fv = parse_version(eco, e["fixed"]) if "fixed" in e else None
                    if fv is not None and cur is not None and fv > cur:
                        out.append(str(e["fixed"]))
    return sorted(set(out), key=lambda s: parse_version(eco, s))
