"""Severity extraction, CVSS v3.x base-score calculation and a transparent risk-priority score."""
import math

_AV = {"N": .85, "A": .62, "L": .55, "P": .2}
_AC = {"L": .77, "H": .44}
_UI = {"N": .85, "R": .62}
_CIA = {"H": .56, "L": .22, "N": 0.0}
SEV_ASSUMED = {"CRITICAL": 9.5, "HIGH": 7.8, "MEDIUM": 5.5, "LOW": 2.5}   # only used when no CVSS score exists


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string, or None if it is not a valid v3 vector."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        if not vector.startswith("CVSS:3"):
            return None
        scope_changed = parts["S"] == "C"
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[parts["PR"]]
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * pr * _UI[parts["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min((impact + expl) * (1.08 if scope_changed else 1), 10))
    except (KeyError, ValueError):
        return None


def label_from_score(score: float) -> str:
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


def severity_info(vuln: dict) -> dict:
    """{'label', 'score', 'basis'}: the label comes from the source; a CVSS score is computed from its vector."""
    score, vector = None, ""
    for s in vuln.get("severity", []) or []:
        raw = str(s.get("score", ""))
        if raw.startswith("CVSS:3"):
            vector, score = raw, cvss3_score(raw)
            break
    src = (vuln.get("database_specific") or {}).get("severity")
    if src:
        label = {"MODERATE": "MEDIUM"}.get(str(src).upper(), str(src).upper())
        return {"label": label, "score": score, "vector": vector, "basis": "source label"}
    if score is not None:
        return {"label": label_from_score(score), "score": score, "vector": vector, "basis": "computed from the source's CVSS vector"}
    return {"label": "UNKNOWN", "score": None, "vector": vector, "basis": "not provided by the source"}


def score_label(score: float) -> str:
    return "CRITICAL" if score >= 75 else "HIGH" if score >= 55 else "MEDIUM" if score >= 35 else "LOW"


def priority(label: str, cvss: float | None, epss: float | None, kev: bool, direct, dependents: int) -> dict:
    """0-100 triage score: 60 severity + 25 exploitation evidence + 15 exposure. A heuristic for ORDERING work."""
    base = cvss if cvss is not None else SEV_ASSUMED.get(label, 5.0)
    sev_pts = base / 10 * 60
    exp_pts = 25.0 if kev else (epss or 0.0) * 25
    expo_pts = {True: 10, False: 5, None: 7}[direct] + min(5, dependents)
    score = round(sev_pts + exp_pts + expo_pts, 1)
    why = [f"severity {label.lower()}" + ("" if cvss is not None or label in SEV_ASSUMED else " (unknown, assumed mid)"),
           "known exploited (CISA KEV)" if kev else (f"EPSS {epss:.1%}" if epss is not None else "no exploit data"),
           {True: "direct dependency", False: "transitive dependency", None: "dependency type unknown"}[direct]]
    if dependents:
        why.append(f"{dependents} package(s) depend on it")
    return {"score": score, "label": score_label(score), "why": "; ".join(why)}
