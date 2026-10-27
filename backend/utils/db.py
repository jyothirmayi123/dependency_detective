"""SQLite: scan history + cache of advisories fetched from OSV.
On Streamlit Community Cloud this file is temporary (lost on restart)."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from backend import config


def _conn():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS advisory_cache(id TEXT PRIMARY KEY, record TEXT, fetched_at TEXT)")
    c.execute("""CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT,
                 mode TEXT, total INTEGER, confirmed INTEGER, report TEXT)""")
    return c


def cache_get(vid: str):
    with closing(_conn()) as c:
        row = c.execute("SELECT record FROM advisory_cache WHERE id=?", (vid,)).fetchone()
    return json.loads(row[0]) if row else None


def cache_put(vid: str, record: dict):
    with closing(_conn()) as c, c:
        c.execute("REPLACE INTO advisory_cache VALUES(?,?,?)",
                  (vid, json.dumps(record), datetime.now(timezone.utc).isoformat(timespec="seconds")))


def cache_all() -> list[dict]:
    with closing(_conn()) as c:
        return [json.loads(r[0]) for r in c.execute("SELECT record FROM advisory_cache")]


def save_scan(report: dict) -> int:
    s = report["summary"]
    with closing(_conn()) as c, c:
        cur = c.execute("INSERT INTO scans(scanned_at,mode,total,confirmed,report) VALUES(?,?,?,?,?)",
                        (report["scanned_at"], report["mode"], s["total"], s["vulnerable"], json.dumps(report)))
        return cur.lastrowid


def list_scans() -> list[dict]:
    with closing(_conn()) as c:
        rows = c.execute("SELECT id,scanned_at,mode,total,confirmed FROM scans ORDER BY id DESC").fetchall()
    return [dict(zip(("id", "scanned_at", "mode", "total", "confirmed"), r)) for r in rows]


def get_scan(scan_id: int):
    with closing(_conn()) as c:
        row = c.execute("SELECT report FROM scans WHERE id=?", (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None
