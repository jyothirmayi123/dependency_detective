"""Java: Maven pom.xml and Gradle build files (build.gradle / build.gradle.kts)."""
import re

from backend.parsers.base import entry, find_line, load_xml, set_version, unresolved

ECO = "Maven"


def _resolve_props(val: str, props: dict) -> str:
    for _ in range(6):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), val)
        if new == val:
            break
        val = new
    return val


def _bad_version(v: str) -> str:
    if "${" in v:
        return "Version uses a property that could not be resolved"
    if v[:1] in "[(" or "," in v:
        return "Version range: exact version unknown"
    if v.upper() in ("LATEST", "RELEASE"):
        return "Floating version (LATEST/RELEASE): exact version unknown"
    return ""


def parse_pom(text: str) -> list[dict]:
    root, out = load_xml(text), []
    props = {el.tag: (el.text or "").strip() for el in root.findall("properties/*")}
    pv = root.findtext("version") or root.findtext("parent/version") or ""
    pg = root.findtext("groupId") or root.findtext("parent/groupId") or ""
    props.update({"project.version": pv.strip(), "pom.version": pv.strip(), "project.groupId": pg.strip()})
    managed = {}
    for d in root.findall("dependencyManagement/dependencies/dependency"):
        g, a, v = (d.findtext(x) or "" for x in ("groupId", "artifactId", "version"))
        if v.strip():
            managed[f"{g.strip()}:{a.strip()}"] = _resolve_props(v.strip(), props)
    for d in root.findall("dependencies/dependency"):
        g = _resolve_props((d.findtext("groupId") or "").strip(), props)
        a = (d.findtext("artifactId") or "").strip()
        if not g or not a:
            continue
        name, v = f"{g}:{a}", (d.findtext("version") or "").strip()
        e = entry(ECO, name, line=find_line(text, f"<artifactId>{a}</artifactId>"), direct=True,
                  scope=(d.findtext("scope") or "").strip())
        note = ""
        if not v and name in managed:
            v, note = managed[name], "Version taken from dependencyManagement"
        elif v:
            v = _resolve_props(v, props)
        if not v:
            unresolved(e, "Version managed by a parent POM/BOM that is not visible here")
        elif _bad_version(v):
            unresolved(e, _bad_version(v), v)
        else:
            set_version(e, v)
            e["note"] = note if e["status"] == "exact" else e["note"]
        out.append(e)
    return out


_CONF = (r"(?:api|implementation|compile|compileOnly|runtimeOnly|runtime|testImplementation|testCompile|"
         r"testRuntimeOnly|testCompileOnly|annotationProcessor|kapt|classpath|developmentOnly|providedCompile)")
_STR = re.compile(rf"\b({_CONF})\b\s*\(?\s*[\"']([^\"':\s]+):([^\"':\s]+)(?::([^\"'\s@]+))?(?:@\w+)?[\"']")
_MAP = re.compile(rf"\b({_CONF})\b\s*\(?\s*group\s*[:=]\s*[\"']([^\"']+)[\"']\s*,\s*name\s*[:=]\s*[\"']([^\"']+)[\"']"
                  rf"(?:\s*,\s*version\s*[:=]\s*[\"']([^\"']+)[\"'])?")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def parse_gradle(text: str) -> list[dict]:
    clean, out = _strip_comments(text), []
    for rx in (_STR, _MAP):
        for m in rx.finditer(clean):
            conf, g, a, v = m.group(1), m.group(2), m.group(3), m.group(4)
            e = entry(ECO, f"{g}:{a}", line=clean.count("\n", 0, m.start()) + 1, raw=m.group(0).strip(),
                      direct=True, scope="test" if conf.lower().startswith("test") else "")
            if not v:
                unresolved(e, "No version (managed by a platform/BOM or plugin)")
            elif "$" in v or "+" in v or v.startswith("latest") or _bad_version(v):
                unresolved(e, "Dynamic/templated version: exact version unknown", v)
            else:
                set_version(e, v)
            out.append(e)
    return sorted(out, key=lambda e: e["line"])
