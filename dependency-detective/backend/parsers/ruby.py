"""Ruby: Gemfile.lock (exact versions + dependency edges + which gems are declared in the Gemfile)."""
import re

from backend.parsers.base import entry, set_version

ECO = "RubyGems"
_SPEC = re.compile(r"^ {4}([^\s(]+) \(([^)]+)\)\s*$")
_DEP = re.compile(r"^ {6}([^\s(]+)")
_TOP = re.compile(r"^ {2}([^\s(!]+)")


def parse_gemfile_lock(text: str) -> list[dict]:
    section, gems, direct, current = None, {}, set(), None
    for raw in text.splitlines():
        if raw and not raw.startswith(" "):
            section, current = raw.strip(), None
            continue
        if section == "GEM":
            m = _SPEC.match(raw)
            if m:
                ver = m.group(2).split("-")[0]               # strip platform suffix (x86_64-linux)
                current = gems.setdefault((m.group(1), ver), {"line": 0, "deps": []})
                continue
            m = _DEP.match(raw)
            if m and current is not None:
                current["deps"].append((m.group(1), None))
        elif section == "DEPENDENCIES":
            m = _TOP.match(raw)
            if m:
                direct.add(m.group(1))
    out = []
    for (name, ver), info in gems.items():
        e = entry(ECO, name, deps=info["deps"])
        if direct:
            e["direct"] = name in direct
        out.append(set_version(e, ver))
    return out
