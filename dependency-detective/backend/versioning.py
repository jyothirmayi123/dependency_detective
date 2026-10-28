"""Version comparison across ecosystems.

PyPI uses PEP 440 (packaging). Every other ecosystem uses a tolerant comparator that understands
semver pre-releases (1.0.0-rc.1 < 1.0.0), Maven qualifiers (2.0-beta9 < 2.0 < 2.0-sp1) and
OpenSSL-style letter suffixes (1.1.1m < 1.1.1n). It is a best-effort approximation: in online mode
OSV's own server-side matching is authoritative.
"""
import re

from packaging.version import InvalidVersion, Version

_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_RELEASE = re.compile(r"\d+(?:\.\d+)*")
_RANK = {"dev": -7, "snapshot": -7, "nightly": -7, "alpha": -5, "a": -5, "beta": -4, "b": -4,
         "milestone": -3, "m": -3, "preview": -2, "pre": -2, "rc": -2, "cr": -2, "candidate": -2,
         "final": 0, "ga": 0, "release": 0, "stable": 0, "sp": 1, "post": 1, "patch": 1, "p": 1}


def _generic(s: str):
    s = str(s).strip()
    if s[:1] in "vV" and s[1:2].isdigit():
        s = s[1:]
    s = s.split("+", 1)[0]                    # build metadata is ignored for ordering
    m = _RELEASE.match(s)
    if not m:
        return None
    rel = [int(x) for x in m.group().split(".")]
    rest = s[m.end():]
    if re.fullmatch(r"[A-Za-z]", rest):        # OpenSSL style: 1.1.1m (a later patch release)
        q = [(1, ord(rest.lower()))]
    else:
        q = []
        for t in _TOKEN.findall(rest):
            if t.isdigit():
                q.append((0, int(t)))
            else:
                rank = _RANK.get(t.lower(), -1)   # unknown words behave like pre-release tags
                if rank != 0:                      # final/ga/release == nothing
                    q.append((rank, 0))
        if not q:
            q = [(0, -1)]                          # plain release: above any pre-release, below post
    while len(rel) > 1 and rel[-1] == 0:
        rel.pop()
    return tuple(rel), tuple(q)


def parse_version(eco: str, s):
    """Return a comparable key, or None if the string is not a usable version."""
    if s is None or str(s).strip() == "":
        return None
    if eco == "PyPI":
        try:
            return Version(str(s))
        except InvalidVersion:
            return None
    return _generic(s)


def release_tuple(eco: str, s) -> tuple:
    k = parse_version(eco, s)
    if k is None:
        return ()
    return tuple(k.release) if eco == "PyPI" else k[0]


def change_type(eco: str, old: str, new: str) -> str:
    """'major' / 'minor' / 'patch' between two versions (by release numbers)."""
    a, b = release_tuple(eco, old), release_tuple(eco, new)
    if not a or not b:
        return "unknown"
    pad = lambda t: (list(t) + [0, 0, 0])[:3]
    a, b = pad(a), pad(b)
    if a[0] != b[0]:
        return "major"
    return "minor" if a[1] != b[1] else "patch"
