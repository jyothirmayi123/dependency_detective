"""Shared helpers for all manifest/lockfile parsers. Parsers only read text: nothing is ever executed."""
import json
import re

from backend.versioning import parse_version


def entry(eco: str, name=None, **kw) -> dict:
    """One dependency line/record. status: exact | unresolved | malformed | skipped."""
    e = {"ecosystem": eco, "line": 0, "raw": "", "name": name, "specifier": "", "version": None,
         "status": "", "note": "", "duplicate_of": None, "direct": None, "deps": [], "scope": ""}
    e.update(kw)
    return e


def set_version(e: dict, version: str, note: str = "") -> dict:
    """Mark exact if the string is a usable version for the entry's ecosystem."""
    if parse_version(e["ecosystem"], version) is not None:
        e.update(status="exact", version=version, specifier=e["specifier"] or f"=={version}")
    else:
        e.update(status="unresolved", note=note or "Version string not recognised")
    return e


def unresolved(e: dict, note: str, spec: str = "") -> dict:
    e.update(status="unresolved", note=note, specifier=spec or e["specifier"])
    return e


def skipped(e: dict, note: str) -> dict:
    e.update(status="skipped", note=note)
    return e


def find_line(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


def load_json(text: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError as ex:
        raise ValueError(f"Invalid JSON ({ex.msg} at line {ex.lineno})")
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object at the top level")
    return data


def load_toml(text: str):
    import tomllib
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as ex:
        raise ValueError(f"Invalid TOML ({ex})")


def load_xml(text: str):
    """Parse XML but refuse DOCTYPE/ENTITY declarations (blocks entity-expansion attacks)."""
    import xml.etree.ElementTree as ET
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("XML containing DOCTYPE/ENTITY declarations is rejected for safety")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as ex:
        raise ValueError(f"Invalid XML ({ex})")
    for el in root.iter():                       # drop namespaces so tags are easy to match
        if isinstance(el.tag, str):
            el.tag = el.tag.split("}", 1)[-1]
    return root
