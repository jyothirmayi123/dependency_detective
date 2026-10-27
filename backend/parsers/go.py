"""Go: go.mod (direct vs `// indirect` is read from the file itself)."""
from backend.parsers.base import entry, set_version

ECO = "Go"


def parse_go_mod(text: str) -> list[dict]:
    out, in_block = [], False
    for no, raw in enumerate(text.splitlines(), 1):
        indirect = "// indirect" in raw
        code = raw.split("//", 1)[0].strip()
        if not code:
            continue
        if code.replace(" ", "") == "require(":
            in_block = True
            continue
        if in_block and code == ")":
            in_block = False
            continue
        if code.startswith("require ") and "(" not in code:
            spec = code[len("require "):]
        elif in_block:
            spec = code
        else:
            continue
        parts = spec.split()
        e = entry(ECO, parts[0] if parts else None, line=no, raw=raw.strip(), direct=not indirect)
        if len(parts) < 2:
            e.update(status="malformed", note="Line could not be parsed")
        else:
            v = parts[1][1:] if parts[1].startswith("v") else parts[1]  # OSV stores Go versions without "v"
            set_version(e, v.removesuffix("+incompatible"))
        out.append(e)
    return out
