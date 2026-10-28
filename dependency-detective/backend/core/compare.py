"""Compare two stored scan reports (newly introduced vs resolved findings). Works with old single-language reports too."""


def _keys(report: dict) -> set:
    return {(f.get("ecosystem", "PyPI"), f["package"], f["version"], f["id"]) for f in report["findings"]}


def diff_reports(old: dict, new: dict) -> dict:
    o, n = _keys(old), _keys(new)
    return {"new": sorted(n - o), "resolved": sorted(o - n), "persisting": sorted(n & o)}
