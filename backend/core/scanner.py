"""Orchestrates: detect+parse -> graph -> advisory lookup -> match -> risk -> remediation -> report dict."""
import json
from datetime import datetime, timezone

from backend import config
from backend.core import graph as dgraph
from backend.core import risk, typosquat
from backend.core.matcher import AdvisoryIndex, fixes_for
from backend.core.remediation import recommend, upgrade_command
from backend.ecosystems import label as eco_label, package_download_url, purl
from backend.parsers import FORMATS, parse_manifest
from backend.services import enrichment, osv_service
from backend.utils import db

STATUS_OF = {"unresolved": "unresolved", "malformed": "malformed", "skipped": "skipped"}


def load_sample() -> dict:
    return json.loads(config.SAMPLE_ADVISORIES.read_text(encoding="utf-8"))


def _offline_advisories() -> tuple[list[dict], str]:
    sample = load_sample()
    merged = {v["id"]: v for v in sample["vulns"]}
    cached = db.cache_all()
    merged.update({v["id"]: v for v in cached})  # previously fetched OSV records win
    meta = sample["meta"]
    src = f"{meta['name']} (snapshot {meta['snapshot_date']}) + {len(cached)} cached OSV record(s)"
    return list(merged.values()), src


def _cves(v: dict) -> list[str]:
    return [i for i in [v["id"], *v.get("aliases", [])] if i.startswith("CVE-")]


def _name(n: str) -> str:
    return n.split("|")[1] + "@" + n.split("|")[2]


def scan(text: str, mode: str = "offline", filename: str = "requirements.txt", enrich: bool = False) -> dict:
    """Scan one file (kept for simple use and backwards compatibility)."""
    return scan_many([(filename, text)], mode, enrich)


def scan_many(files: list[tuple[str, str]], mode: str = "offline", enrich: bool = False) -> dict:
    # ---- 1. parse every file -------------------------------------------------------------
    entries, file_info = [], []
    for fname, text in files:
        fmt, items = parse_manifest(fname, text)
        for e in items:
            e["file"], e["format"] = fname, fmt
        file_info.append({"file": fname, "format": fmt, "ecosystem": FORMATS[fmt][0], "kind": FORMATS[fmt][2], "entries": len(items)})
        entries += items
    if len(entries) > config.MAX_PACKAGES:
        raise ValueError(f"Too many dependencies ({len(entries)}); the limit is {config.MAX_PACKAGES}.")

    # ---- 2. dependency graph (direct/transitive, paths) ----------------------------------
    G = dgraph.build_graph(entries)
    paths = dgraph.paths_from_roots(G, entries)

    # ---- 3. advisory lookup ---------------------------------------------------------------
    pairs = sorted({(e["ecosystem"], e["name"], e["version"]) for e in entries if e["status"] == "exact"})
    found, warnings = {}, []
    if mode == "online":
        source = "OSV.dev live API (api.osv.dev)"
        try:
            ids_per_pair = osv_service.query_batch(pairs)
            records = osv_service.get_vulns(sorted({i for ids in ids_per_pair for i in ids}))
            for pair, ids in zip(pairs, ids_per_pair):
                found[pair] = [records[i] for i in ids if not records[i].get("withdrawn")]
        except Exception as ex:
            found = None
            warnings.append(f"OSV lookup unavailable ({type(ex).__name__}). Switch to offline mode or retry.")
    else:
        advisories, source = _offline_advisories()
        index = AdvisoryIndex(advisories)
        found = {p: index.find(*p) for p in pairs}

    # ---- 4. exploit signals (optional) ----------------------------------------------------
    epss, kev = {}, set()
    if enrich and found:
        cves = sorted({c for vs in found.values() for v in vs for c in _cves(v)})
        try:
            kev, epss = enrichment.fetch_kev(), (enrichment.fetch_epss(cves) if cves else {})
        except Exception as ex:
            warnings.append(f"Exploit-signal lookup (EPSS/KEV) failed ({type(ex).__name__}); risk scores use severity only.")
            kev, epss = set(), {}

    # ---- 5. match results back onto entries -----------------------------------------------
    packages, findings, sev_count, seen_f, groups = [], [], {}, set(), {}
    for e in entries:
        status = STATUS_OF.get(e["status"])
        vulns, rec = [], {"version": None, "note": "", "change": None}
        if e["status"] == "exact":
            if found is None:
                status = "lookup_unavailable"
            else:
                vulns = found[(e["ecosystem"], e["name"], e["version"])]
                status = "vulnerable" if vulns else "no_match"
                rec = recommend(e["name"], e["version"], vulns, e["ecosystem"])
        node = e.get("node")
        via = [_name(n) for n in paths.get(node, [])] if node else []
        top_risk = 0.0
        for v in vulns:
            key = (e["ecosystem"], e["name"], e["version"], v["id"])
            sev = risk.severity_info(v)
            cves = _cves(v)
            ep = max((epss[c] for c in cves if c in epss), default=None)
            is_kev = any(c in kev for c in cves)
            pr = risk.priority(sev["label"], sev["score"], ep, is_kev, e["direct"], dgraph.blast_radius(G, node) if node else 0)
            top_risk = max(top_risk, pr["score"])
            if key in seen_f:
                continue
            seen_f.add(key)
            sev_count[sev["label"]] = sev_count.get(sev["label"], 0) + 1
            findings.append({
                "ecosystem": e["ecosystem"], "package": e["name"], "version": e["version"], "id": v["id"], "file": e["file"],
                "line": e["line"], "aliases": v.get("aliases", []), "summary": v.get("summary") or "No summary provided",
                "severity": sev["label"], "severity_basis": sev["basis"], "cvss_score": sev["score"], "cvss_vector": sev["vector"],
                "epss": ep, "kev": is_kev, "risk": pr["score"], "risk_label": pr["label"], "risk_why": pr["why"],
                "direct": e["direct"], "via": via, "purl": purl(e["ecosystem"], e["name"], e["version"]),
                "fixed_in": fixes_for(v, e["name"], e["version"], e["ecosystem"]), "modified": v.get("modified", ""),
                "references": [r["url"] for r in v.get("references", []) if r.get("url")][:5],
                "source_url": f"https://osv.dev/vulnerability/{v['id']}",
            })
        if vulns:
            g = groups.setdefault((e["ecosystem"], e["name"], e["version"]), {"e": e, "rec": rec, "ids": set(), "risk": 0.0, "via": via})
            g["ids"] |= {v["id"] for v in vulns}
            g["risk"] = max(g["risk"], top_risk)
        packages.append({
            "file": e["file"], "line": e["line"], "ecosystem": e["ecosystem"], "package": e["name"] or e["raw"],
            "specifier": e["specifier"], "version": e["version"], "scope": e["scope"], "direct": e["direct"],
            "status": status, "advisories": len(vulns), "risk": top_risk or None, "recommended": rec["version"],
            "purl": purl(e["ecosystem"], e["name"], e["version"]) if e["name"] else "",
            "note": " ".join(filter(None, [e["note"] + (".")*bool(e["note"]), rec["note"]]))})
    findings.sort(key=lambda f: -f["risk"])

    # ---- 6. prioritised fix plan ---------------------------------------------------------
    fix_plan = []
    for (eco, name, ver), g in groups.items():
        t, e = g["rec"]["version"], g["e"]
        score = g["risk"]
        parent = g["via"][0] if g["via"] and e["direct"] is False else None
        if t:
            if e["direct"] is not False:
                act = f"Upgrade {name} {ver} -> {t}"
            elif parent:
                act = f"Upgrade {name} {ver} -> {t} (pulled in via {parent}; update {parent.split('@')[0]} or pin/override {name})"
            else:
                act = f"Upgrade {name} {ver} -> {t} (indirect dependency: update whatever requires it, or require {t}+ directly)"
        else:
            act = "No verified fix in the advisory data: review the advisories, mitigate or consider replacing the package"
        fix_plan.append({"ecosystem": eco, "package": name, "current": ver, "target": t, "change": g["rec"]["change"],
                         "direct": e["direct"], "via": g["via"], "advisories": sorted(g["ids"]), "max_risk": score,
                         "risk_label": risk.score_label(score),
                         "action": act, "command": upgrade_command(eco, name, t, e["direct"]) if t else "",
                         "upgrade_url": package_download_url(eco, name, t) if t else None, "file": e["file"]})
    fix_plan.sort(key=lambda f: -f["max_risk"])

    # ---- 7. supply-chain signals ---------------------------------------------------------
    signals, seen_s = [], set()
    for e in entries:
        hit = typosquat.check(e["ecosystem"], e["name"]) if e["name"] else None
        if hit and (e["ecosystem"], e["name"]) not in seen_s:
            seen_s.add((e["ecosystem"], e["name"]))
            signals.append({"kind": "possible typosquat", "ecosystem": e["ecosystem"], "package": e["name"],
                            "file": e["file"], "line": e["line"], **hit})

    # ---- 8. summary ------------------------------------------------------------------------
    count = lambda s: sum(p["status"] == s for p in packages)
    by_eco = {}
    for p in packages:
        d = by_eco.setdefault(p["ecosystem"], {"label": eco_label(p["ecosystem"]), "total": 0, "vulnerable": 0})
        d["total"] += 1
        d["vulnerable"] += p["status"] == "vulnerable"
    vuln_nodes = {e["node"] for e in entries if e.get("node") and e["status"] == "exact" and found and found.get((e["ecosystem"], e["name"], e["version"]))}
    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode, "source": source if found is not None else "OSV.dev (unreachable)",
        "enriched": bool(enrich and (kev or epss)), "files": file_info,
        "summary": {"total": len(packages), "vulnerable": count("vulnerable"), "no_match": count("no_match"),
                    "unresolved": count("unresolved"), "lookup_unavailable": count("lookup_unavailable"),
                    "malformed": count("malformed"), "skipped": count("skipped"),
                    "advisories": len(findings), "severity": sev_count, "by_ecosystem": by_eco,
                    "transitive": sum(1 for p in packages if p["direct"] is False), "signals": len(signals)},
        "packages": packages, "findings": findings, "fix_plan": fix_plan, "signals": signals,
        "graph": dgraph.to_dict(G, entries, vuln_nodes), "warnings": warnings,
        "disclaimer": "No matching record means none was found in the source used, not that a package is safe. "
                      "Upgrade suggestions are not guaranteed to be compatible. Risk scores only help order the work.",
    }
