"""Export a scan report as JSON, CSV, Markdown, SARIF 2.1.0, CycloneDX 1.5 SBOM or a fixed requirements file."""
import json

import pandas as pd

from backend.ecosystems import label as eco_label

LABEL = {"vulnerable": "Confirmed match", "no_match": "No matching record", "unresolved": "Unresolved version",
         "lookup_unavailable": "Lookup unavailable", "malformed": "Malformed line", "skipped": "Skipped option"}
INCOMPLETE = ("unresolved", "lookup_unavailable", "malformed", "skipped")
DEP = {True: "direct", False: "transitive", None: "unknown"}


def to_json(r: dict) -> str:
    return json.dumps(r, indent=2)


def to_csv(r: dict) -> str:
    df = pd.DataFrame(r["packages"]).assign(status=lambda d: d["status"].map(LABEL))
    df["direct"] = df["direct"].map(DEP)
    return df.to_csv(index=False)


def to_markdown(r: dict) -> str:
    s = r["summary"]
    md = ["# Dependency Detective scan report", f"- Scanned (UTC): {r['scanned_at']}", f"- Mode: {r['mode']}",
          f"- Advisory source: {r['source']}",
          f"- Files: " + ", ".join(f"{f['file']} ({f['format']})" for f in r.get("files", [])),
          f"- Packages: {s['total']} | Confirmed matches: {s['vulnerable']} | Unresolved: {s['unresolved']} | "
          f"Lookup unavailable: {s['lookup_unavailable']} | Transitive: {s.get('transitive', 0)}", ""]
    if s.get("by_ecosystem"):
        md += ["## By language", "| Ecosystem | Packages | Vulnerable |", "|---|---|---|"]
        md += [f"| {d['label']} | {d['total']} | {d['vulnerable']} |" for d in s["by_ecosystem"].values()] + [""]
    md += ["## Fix plan (highest risk first)"]
    if r.get("fix_plan"):
        md += ["| Risk | Package | Action | Advisories |", "|---|---|---|---|"]
        md += [f"| {f['risk_label']} ({f['max_risk']}) | {f['package']} ({eco_label(f['ecosystem'])}) | {f['action']} | "
               f"{', '.join(f['advisories'])} |" for f in r["fix_plan"]]
    else:
        md.append("Nothing to fix in the source used.")
    md += ["", "## Confirmed findings"]
    if not r["findings"]:
        md.append("None found in the source used.")
    for f in r["findings"]:
        md += [f"### {f['package']}=={f['version']} ({eco_label(f.get('ecosystem', 'PyPI'))}): {f['id']}",
               f"- Severity: {f['severity']} ({f.get('severity_basis', 'source')})"
               + (f", CVSS {f['cvss_score']}" if f.get("cvss_score") else ""),
               f"- Priority: {f.get('risk_label', '-')} ({f.get('risk', '-')}/100): {f.get('risk_why', '')}",
               f"- Summary: {f['summary']}", f"- Fixed in: {', '.join(f['fixed_in']) or 'not stated'}"]
        if f.get("via"):
            md.append(f"- Introduced via: {' -> '.join(f['via'])}")
        md.append(f"- Reference: {f['source_url']}")
    if r.get("signals"):
        md += ["", "## Supply-chain signals (heuristic, verify manually)"]
        md += [f"- {x['package']} ({x['file']}): {x['detail']}" for x in r["signals"]]
    md += ["", "## Suggested upgrades (evidence-based, not guaranteed compatible)"]
    md += [f"- {p['package']}: {p['version']} -> {p['recommended']}" for p in r["packages"] if p["recommended"]] or ["None."]
    md += ["", "## Incomplete checks"]
    md += [f"- {p.get('file', '')} line {p['line']} `{p['package']}`: {LABEL[p['status']]}. {p['note']}"
           for p in r["packages"] if p["status"] in INCOMPLETE] or ["None."]
    md += ["", f"> {r['disclaimer']}"]
    return "\n".join(md)


def to_fixed_requirements(r: dict) -> str:
    """requirements.txt lines for direct Python packages that have a verified upgrade."""
    lines = [f"{f['package']}=={f['target']}  # was {f['current']} ({', '.join(f['advisories'])})"
             for f in r.get("fix_plan", []) if f["ecosystem"] == "PyPI" and f["target"] and f["direct"] is not False]
    return "\n".join(["# Suggested upgrades from Dependency Detective: test before merging"] + lines) + "\n"


def to_upgrade_plan_csv(r: dict) -> str:
    """CSV of verified upgrade suggestions across all ecosystems."""
    df = pd.DataFrame([
        {"ecosystem": f["ecosystem"], "package": f["package"], "current": f["current"],
         "suggested": f["target"], "dependency_type": DEP[f["direct"]], "file": f["file"],
         "advisories": ", ".join(f["advisories"]), "priority": f["max_risk"], "command": f["command"],
         "download_url": f.get("upgrade_url") or ""}
        for f in r.get("fix_plan", []) if f["target"]
    ], columns=["ecosystem", "package", "current", "suggested", "dependency_type", "file",
                "advisories", "priority", "command", "download_url"])
    return df.to_csv(index=False)


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def to_sarif(r: dict) -> str:
    """SARIF 2.1.0: upload to GitHub code scanning or any SARIF viewer."""
    rules, results = {}, []
    for f in r["findings"]:
        rules.setdefault(f["id"], {"id": f["id"], "name": f["id"], "shortDescription": {"text": f["summary"][:200]},
                                   "helpUri": f["source_url"], "properties": {"severity": f["severity"], "tags": ["security", "dependency"]}})
        fix = f"Upgrade to {', '.join(f['fixed_in'])}." if f["fixed_in"] else "No fixed version listed."
        results.append({"ruleId": f["id"], "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                        "message": {"text": f"{f['package']} {f['version']} ({eco_label(f['ecosystem'])}) is affected by {f['id']}: {f['summary']} {fix}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                           "region": {"startLine": max(1, f.get("line") or 1)}}}],
                        "properties": {"risk": f["risk"], "purl": f["purl"], "direct": f["direct"]}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "Dependency Detective", "informationUri": "https://osv.dev",
                                         "rules": list(rules.values())}}, "results": results}]}
    return json.dumps(doc, indent=2)


def to_cyclonedx(r: dict) -> str:
    """CycloneDX 1.5 SBOM with vulnerabilities and the dependency graph."""
    comps, ref_of = {}, {}
    for p in r["packages"]:
        if p["version"] and p["purl"]:
            ref_of[(p["ecosystem"], p["package"], p["version"])] = p["purl"]
            comps[p["purl"]] = {"type": "library", "bom-ref": p["purl"], "name": p["package"], "version": p["version"], "purl": p["purl"]}
    vulns = {}
    for f in r["findings"]:
        v = vulns.setdefault(f["id"], {"id": f["id"], "source": {"name": "OSV", "url": f["source_url"]}, "description": f["summary"],
                                       "ratings": [], "affects": []})
        if not v["ratings"]:
            rating = {"source": {"name": "OSV"}, "severity": f["severity"].lower()}
            if f.get("cvss_score") is not None:
                rating.update(score=f["cvss_score"], method="CVSSv31", vector=f.get("cvss_vector", ""))
            v["ratings"].append(rating)
        v["affects"].append({"ref": f["purl"]})
    nodes = {n["id"]: n for n in r.get("graph", {}).get("nodes", [])}
    deps = {}
    for a, b in r.get("graph", {}).get("edges", []):
        pa, pb = nodes[a], nodes[b]
        ra, rb = ref_of.get((pa["ecosystem"], pa["package"], pa["version"])), ref_of.get((pb["ecosystem"], pb["package"], pb["version"]))
        if ra and rb:
            deps.setdefault(ra, []).append(rb)
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"timestamp": r["scanned_at"], "tools": {"components": [{"type": "application", "name": "Dependency Detective"}]}},
           "components": list(comps.values()), "vulnerabilities": list(vulns.values()),
           "dependencies": [{"ref": k, "dependsOn": sorted(set(v))} for k, v in deps.items()]}
    return json.dumps(doc, indent=2)
