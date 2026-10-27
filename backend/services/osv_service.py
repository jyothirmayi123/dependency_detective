"""OSV.dev client (free, no API key). Handles pagination and fetches advisory details in parallel.
Advisory details are cached in SQLite."""
from concurrent.futures import ThreadPoolExecutor

import requests

from backend import config
from backend.utils import db

TIMEOUT = 15
BATCH = 500
MAX_PAGES = 20
WORKERS = 8


def query_batch(pairs: list[tuple]) -> list[list[str]]:
    """Advisory ids per (ecosystem, name, version) triple, following OSV's next_page_token pagination.
    Raises on network/API errors."""
    out: list[list[str]] = [[] for _ in pairs]
    pending = [(i, {"package": {"name": n, "ecosystem": eco}, "version": v}) for i, (eco, n, v) in enumerate(pairs)]
    for _ in range(MAX_PAGES):
        if not pending:
            break
        nxt = []
        for s in range(0, len(pending), BATCH):
            chunk = pending[s:s + BATCH]
            r = requests.post(f"{config.OSV_API_URL}/querybatch", json={"queries": [q for _, q in chunk]}, timeout=TIMEOUT)
            r.raise_for_status()
            for (i, q), res in zip(chunk, r.json()["results"]):
                out[i] += [x["id"] for x in res.get("vulns", [])]
                if res.get("next_page_token"):
                    nxt.append((i, {**q, "page_token": res["next_page_token"]}))
        pending = nxt
    return out


def _fetch(vid: str) -> dict:
    r = requests.get(f"{config.OSV_API_URL}/vulns/{vid}", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def get_vulns(ids: list[str]) -> dict[str, dict]:
    """Full records for many ids: cache first, the rest downloaded in parallel (DB writes stay in this thread)."""
    recs = {i: c for i in ids if (c := db.cache_get(i))}
    missing = [i for i in ids if i not in recs]
    if missing:
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for vid, rec in zip(missing, pool.map(_fetch, missing)):
                db.cache_put(vid, rec)
                recs[vid] = rec
    return recs


def get_vuln(vid: str) -> dict:
    return get_vulns([vid])[vid]
