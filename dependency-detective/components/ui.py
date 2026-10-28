"""Reusable UI pieces: theme CSS, hero, metric cards, badges."""
import streamlit as st

STATUS = {"vulnerable": ("Confirmed match", "#B42318"), "no_match": ("No matching record", "#2F7D4F"),
          "unresolved": ("Unresolved version", "#B7791F"), "lookup_unavailable": ("Lookup unavailable", "#667085"),
          "malformed": ("Malformed line", "#7A3E9D"), "skipped": ("Skipped option", "#475467")}
STATUS_HELP = {
    "vulnerable": "An advisory matches this package and version; this does not prove the vulnerable code is reachable.",
    "no_match": "No advisory was found in the selected data source; this does not prove the package is safe.",
    "unresolved": "An exact version could not be determined, so the package could not be checked reliably.",
    "lookup_unavailable": "The advisory source could not be queried, so the check is incomplete.",
    "malformed": "This dependency entry could not be parsed and was not checked.",
}
SEV = {"CRITICAL": "#7A1212", "HIGH": "#B42318", "MODERATE": "#C77700", "MEDIUM": "#C77700", "LOW": "#2563A8", "UNKNOWN": "#667085"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
html, body, [class*="st-"], .stMarkdown { font-family: 'IBM Plex Sans', sans-serif; }
h1, h2, h3 { font-family: 'Fraunces', serif !important; letter-spacing: -0.01em; }
.block-container { padding-top: 1.6rem; max-width: 1150px; }
.dd-hero { background: #14212B; color: #F6F5F2; border-radius: 6px; padding: 28px 32px; margin-bottom: 20px;
  border-left: 8px solid #E8A33D; }
.dd-hero h1 { color: #F6F5F2; margin: 0 0 6px; font-size: 2.1rem; }
.dd-hero p { margin: 0; color: #C9D3DA; max-width: 62ch; line-height: 1.55; }
.dd-hero code { background: #22333F; color: #E8A33D; padding: 2px 6px; border-radius: 3px; font-family: 'IBM Plex Mono', monospace; }
.dd-stat { background: #fff; border: 1px solid #DAD7CF; border-top: 4px solid var(--c); border-radius: 4px; padding: 12px 14px; }
.dd-stat .n { font-family: 'Fraunces', serif; font-size: 2rem; line-height: 1.1; color: var(--c); }
.dd-stat .l { font-size: .85rem; color: #4B5B66; }
.dd-stat .d { display: block; margin-top: 4px; font-size: .72rem; line-height: 1.35; color: #5B6B76; }
.dd-badge { display: inline-block; padding: 2px 9px; border-radius: 3px; font-size: .78rem; font-weight: 600; color: #fff; background: var(--c); }
.dd-adv { background: #fff; border: 1px solid #DAD7CF; border-left: 5px solid var(--c); border-radius: 4px; padding: 12px 16px; margin: 8px 0; }
.dd-adv .t { font-family: 'IBM Plex Mono', monospace; font-weight: 500; }
.dd-fix { background: #E9F3EE; border: 1px solid #B9D8C8; border-radius: 4px; padding: 10px 14px; margin-top: 8px; }
.dd-warn { background: #FFF4DC; border: 1px solid #EBCB85; border-radius: 4px; padding: 10px 14px; margin: 8px 0; }
.stButton > button[kind="primary"] { border-radius: 4px; font-weight: 600; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
</style>"""


def setup(title="Dependency Detective"):
    st.set_page_config(page_title=title, page_icon="🔎", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)


def hero():
    st.markdown("""<div class="dd-hero"><h1>Dependency Detective</h1>
    <p>Scan dependency files for <code>Python</code> <code>JavaScript</code> <code>Java</code> <code>C/C++</code> <code>Go</code>
    <code>Rust</code> <code>Ruby</code> <code>PHP</code> <code>.NET</code> against public vulnerability records, trace each risk through the
    dependency tree and get a prioritised fix plan. Anything we could not check is listed separately instead of being called safe.</p></div>""", unsafe_allow_html=True)


def stat(col, value, label, color, description=""):
    col.markdown(f'<div class="dd-stat" style="--c:{color}"><div class="n">{value}</div><div class="l">{label}</div>'
                 f'<small class="d">{description}</small></div>',
                 unsafe_allow_html=True)


def badge(text, color):
    return f'<span class="dd-badge" style="--c:{color}">{text}</span>'


def sev_color(sev: str) -> str:
    return SEV.get(sev.split()[0], "#667085")


def dep_label(direct) -> str:
    return {True: "direct", False: "transitive", None: "unknown"}[direct]
