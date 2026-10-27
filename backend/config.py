"""Central settings. Reads st.secrets first, then .env / environment."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()  # local .env (ignored by Git)
except ImportError:
    pass

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "dd.sqlite"                         # history + advisory cache
SAMPLE_ADVISORIES = ROOT / "data" / "sample" / "advisories_sample.json"
SAMPLE_REQUIREMENTS = ROOT / "data" / "sample" / "requirements.txt"
SAMPLE_DIR = ROOT / "data" / "sample"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024     # lockfiles are bigger than requirements.txt
MAX_FILES = 20
MAX_PACKAGES = 5000


def get_setting(name, default=None):
    try:
        import streamlit as st
        return st.secrets[name]
    except Exception:
        return os.getenv(name, default)


OSV_API_URL = get_setting("OSV_API_URL", "https://api.osv.dev/v1")
EPSS_API_URL = get_setting("EPSS_API_URL", "https://api.first.org/data/v1/epss")
KEV_URL = get_setting("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
