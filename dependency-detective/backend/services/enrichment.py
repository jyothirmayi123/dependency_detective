"""Optional exploit-likelihood signals (free, no key): FIRST EPSS scores and the CISA Known Exploited Vulnerabilities list."""
import requests

from backend import config

TIMEOUT = 15


def fetch_kev() -> set[str]:
    r = requests.get(config.KEV_URL, timeout=TIMEOUT)
    r.raise_for_status()
    return {v["cveID"] for v in r.json().get("vulnerabilities", [])}


def fetch_epss(cves: list[str]) -> dict[str, float]:
    """CVE -> probability (0-1) of exploitation in the next 30 days."""
    out, cves = {}, sorted(set(cves))
    for i in range(0, len(cves), 50):
        r = requests.get(config.EPSS_API_URL, params={"cve": ",".join(cves[i:i + 50])}, timeout=TIMEOUT)
        r.raise_for_status()
        out.update({d["cve"]: float(d["epss"]) for d in r.json().get("data", [])})
    return out
