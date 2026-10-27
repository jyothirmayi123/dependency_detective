""".NET: *.csproj / *.fsproj / *.vbproj, Directory.Packages.props, packages.config."""
import re

from backend.parsers.base import entry, find_line, load_xml, set_version, unresolved

ECO = "NuGet"


def _nuget_version(e: dict, v: str):
    v = (v or "").strip()
    m = re.fullmatch(r"\[\s*([^,\[\]()\s]+)\s*\]", v)           # [1.2.3] = exactly 1.2.3
    if m:
        return set_version(e, m.group(1))
    if not v:
        return unresolved(e, "No version (central package management or imported props)")
    if "$(" in v:
        return unresolved(e, "Version uses an MSBuild property", v)
    if "*" in v or v[:1] in "[(" or "," in v:
        return unresolved(e, "Floating/range version: exact version unknown", v)
    return set_version(e, v)


def parse_csproj(text: str) -> list[dict]:
    root, out = load_xml(text), []
    for el in root.iter():
        if el.tag not in ("PackageReference", "PackageVersion"):
            continue
        name = el.get("Include") or el.get("Update")
        if not name:
            continue
        v = el.get("Version") or el.get("VersionOverride") or el.findtext("Version") or ""
        e = entry(ECO, name.lower(), line=find_line(text, f'"{name}"'), direct=el.tag == "PackageReference",
                  scope="build" if el.get("PrivateAssets") == "all" else "")
        out.append(_nuget_version(e, v))
    return out


def parse_packages_config(text: str) -> list[dict]:
    root, out = load_xml(text), []
    for el in root.iter("package"):
        if el.get("id"):
            e = entry(ECO, el.get("id").lower(), line=find_line(text, f'id="{el.get("id")}"'), direct=True)
            out.append(_nuget_version(e, el.get("version") or ""))
    return out
