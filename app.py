"""Dependency Detective: Streamlit frontend. All logic lives in backend/."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from backend import config
from backend.core import graph as dgraph
from backend.core.scanner import scan_many
from backend.ecosystems import label as eco_label
from backend.parsers import FORMATS, SUPPORTED_EXT, detect_format
from backend.utils import db
from backend.utils.report import (INCOMPLETE, LABEL, to_csv, to_cyclonedx, to_fixed_requirements, to_json,
                                  to_markdown, to_sarif, to_upgrade_plan_csv)
from backend.utils.validators import validate_text, validate_upload
from components import ui

ui.setup()
ui.hero()
ss = st.session_state
ss.setdefault("demo", None)

# ---------- sidebar ----------
with st.sidebar:
    st.header("Scan settings")
    mode_label = st.radio("Advisory source", ["Offline (bundled + cached data)", "Online (OSV.dev)"],
                          help="Online needs internet and is authoritative. Offline uses the bundled sample snapshot "
                               "and any records cached earlier (version matching for non-Python languages is approximate).")
    mode = "online" if mode_label.startswith("Online") else "offline"
    enrich = st.toggle("Add exploit signals (EPSS + CISA KEV)", value=False,
                       help="Needs internet. Raises the priority of vulnerabilities that are being exploited or likely to be.")
    st.caption("Online results are cached, so they also work offline afterwards.")
    st.divider()
    st.caption("Privacy: files are processed in memory and only the scan report is stored locally. Do not upload private data.")
    with st.expander("Supported files"):
        st.caption("  \n".join(f"`{k}` · {eco_label(v[0])}" for k, v in FORMATS.items()))

# ---------- input ----------
left, right = st.columns([3, 2])
with right:
    ups = st.file_uploader("Upload dependency files (several allowed)", type=SUPPORTED_EXT, accept_multiple_files=True,
                           help="Lockfiles (package-lock.json, Cargo.lock, poetry.lock...) give exact versions and the full dependency tree.")
    b1, b2 = st.columns(2)
    if b1.button("Load multi-language demo", width="stretch"):
        ss.demo = [(f.name, f.read_text(encoding="utf-8")) for f in sorted(config.SAMPLE_DIR.iterdir())
                   if f.is_file() and f.name != "advisories_sample.json"]
    if ss.demo and b2.button("Clear demo", width="stretch"):
        ss.demo = None
        st.rerun()
    if ss.demo:
        st.caption("Demo loaded: " + ", ".join(n for n, _ in ss.demo))
with left:
    fmt_pick = st.selectbox("Format of pasted text", ["Auto-detect"] + list(FORMATS))
    pasted = st.text_area("Or paste a dependency file", height=170, placeholder="flask==2.2.0\nrequests==2.28.0")

if st.button("Scan dependencies", type="primary"):
    try:
        files = [(u.name, validate_upload(u.name, u.getvalue())) for u in ups] + list(ss.demo or [])
        if pasted.strip():
            text = validate_text(pasted)
            name = "pasted" if fmt_pick == "Auto-detect" else fmt_pick.replace("*", "pasted")
            files.append((name, text))
        if not files:
            raise ValueError("Nothing to scan. Upload files, paste a dependency file or load the demo.")
        if len(files) > config.MAX_FILES:
            raise ValueError(f"Too many files (limit {config.MAX_FILES}).")
        with st.spinner("Scanning..."):
            report = scan_many(files, mode, enrich)
            db.save_scan(report)
        ss.report = report
    except ValueError as err:
        st.warning(str(err))
    except Exception:
        st.error("Something went wrong during the scan. Please try again.")

# ---------- results ----------
r = ss.get("report")
if not r:
    st.info("Upload dependency files or load the demo, then choose **Scan dependencies**.")
    st.stop()

for w in r["warnings"]:
    st.markdown(f'<div class="dd-warn">⚠️ {w}</div>', unsafe_allow_html=True)
s = r["summary"]
st.caption(f"Source: {r['source']} · {len(r.get('files', []))} file(s) · scanned {r['scanned_at']} UTC"
           + (" · exploit signals on" if r.get("enriched") else ""))
cols = st.columns(5)
for c, (k, v) in zip(cols, [("vulnerable", "#B42318"), ("no_match", "#2F7D4F"), ("unresolved", "#B7791F"),
                            ("lookup_unavailable", "#667085"), ("malformed", "#7A3E9D")]):
    ui.stat(c, s[k], LABEL[k], v, ui.STATUS_HELP[k])
st.write("")
if s.get("by_ecosystem"):
    st.markdown(" ".join(
        f'<span class="dd-badge" style="--c:{"#B42318" if d["vulnerable"] else "#2F7D4F"}">{d["label"]}: {d["vulnerable"]}/{d["total"]} vulnerable</span>'
        for d in s["by_ecosystem"].values()), unsafe_allow_html=True)
    st.write("")

t1, t2, t3, t4, t5, t6 = st.tabs(["Findings", "Fix plan", "Dependency graph", "All packages", "Charts", "Export"])

with t1:
    if not r["findings"]:
        st.success("No advisories matched in the source used. This does not prove the packages are safe.")
    else:
        st.caption("Ordered by priority score (0-100): severity + exploitation evidence + exposure. It orders the work; it is not a verdict.")
    pk = {}
    for f in r["findings"]:
        pk.setdefault((f.get("ecosystem", "PyPI"), f["package"], f["version"]), []).append(f)
    recs = {(p["ecosystem"], p["package"]): p for p in r["packages"] if p["recommended"] or p["note"]}
    for (eco, name, ver), fs in pk.items():
        top = max(f["risk"] for f in fs)
        with st.expander(f"[{eco_label(eco)}] {name} {ver}: {len(fs)} advisor{'y' if len(fs) == 1 else 'ies'} · priority {top:.0f}",
                         expanded=len(pk) <= 3):
            if fs[0]["via"] and fs[0]["direct"] is False:
                st.markdown("**Introduced via:** " + " → ".join(f"`{v}`" for v in fs[0]["via"]))
            for f in fs:
                col = ui.sev_color(f["severity"])
                al = f" · {', '.join(f['aliases'])}" if f["aliases"] else ""
                tags = ui.badge(f["severity"], col) + " " + ui.badge(f"priority {f['risk']:.0f}", ui.sev_color(f["risk_label"]))
                if f.get("kev"):
                    tags += " " + ui.badge("KNOWN EXPLOITED", "#7A1212")
                if f.get("epss") is not None:
                    tags += " " + ui.badge(f"EPSS {f['epss']:.0%}", "#475467")
                cv = f" · CVSS {f['cvss_score']}" if f.get("cvss_score") is not None else ""
                st.markdown(f'<div class="dd-adv" style="--c:{col}"><span class="t">{f["id"]}</span>{al} {tags}<br>{f["summary"]}<br>'
                            f'<small>Fixed in: {", ".join(f["fixed_in"]) or "not stated"}{cv} · {f["risk_why"]} · '
                            f'<a href="{f["source_url"]}" target="_blank">OSV record</a></small></div>', unsafe_allow_html=True)
                if f["references"]:
                    st.caption("References: " + " · ".join(f"[{i + 1}]({u})" for i, u in enumerate(f["references"])))
            p = recs.get((eco, name))
            if p and p["recommended"]:
                st.markdown(f'<div class="dd-fix"><b>Suggested upgrade:</b> {name} {ver} → <b>{p["recommended"]}</b><br>'
                            f'<small>{p["note"]}</small></div>', unsafe_allow_html=True)
            elif p:
                st.markdown(f'<div class="dd-warn"><b>No verified upgrade.</b> {p["note"]}</div>', unsafe_allow_html=True)
    if r.get("signals"):
        st.subheader("Supply-chain signals")
        st.caption("Heuristic hints to double-check, not proof of anything malicious.")
        for x in r["signals"]:
            st.markdown(f'<div class="dd-warn"><b>{x["package"]}</b> ({eco_label(x["ecosystem"])}, {x["file"]}): {x["detail"]}</div>', unsafe_allow_html=True)
    incomplete = [p for p in r["packages"] if p["status"] in INCOMPLETE]
    if incomplete:
        st.subheader("Incomplete checks")
        st.caption("These lines were not checked against advisories.")
        st.dataframe(pd.DataFrame(incomplete).assign(status=lambda d: d["status"].map(LABEL))
                     [["file", "line", "package", "specifier", "status", "note"]], hide_index=True, width="stretch")

with t2:
    if not r["fix_plan"]:
        st.success("Nothing to fix in the source used.")
    else:
        st.caption("Highest priority first. Commands are hints: review the changelog, run your tests, then re-scan.")
        if any(f["target"] for f in r["fix_plan"]):
            st.download_button("Download upgrade plan (CSV)", to_upgrade_plan_csv(r),
                               "dependency-upgrade-plan.csv", mime="text/csv")
        for f in r["fix_plan"]:
            tone = "dd-fix" if f["target"] else "dd-warn"
            st.markdown(f'<div class="{tone}">{ui.badge(f["risk_label"], ui.sev_color(f["risk_label"]))} <b>{f["action"]}</b><br>'
                        f'<small>{eco_label(f["ecosystem"])} · {ui.dep_label(f["direct"])} · {", ".join(f["advisories"])}'
                        + (f' · {f["change"]} change' if f["change"] else "") + '</small>'
                        + (f'<br><code>{f["command"]}</code>' if f["command"] else "") + '</div>', unsafe_allow_html=True)
            if f.get("upgrade_url"):
                st.link_button("Download suggested version", f["upgrade_url"])
            elif f["target"]:
                st.caption("A direct download link is not available for this package registry.")

with t3:
    gd = r.get("graph", {"nodes": [], "edges": []})
    st.caption("Direct dependencies sit on the left; each step right is one more level of transitive dependency.")
    only = st.toggle("Only show chains that lead to a vulnerable package", value=True) if len(gd["nodes"]) > 30 or any(n["vulnerable"] for n in gd["nodes"]) else False
    if only and not any(n["vulnerable"] for n in gd["nodes"]):
        st.info("No vulnerable packages to trace.")
    elif not gd["edges"]:
        st.info("These files list no dependency relationships (manifests like requirements.txt, pom.xml or go.mod). "
                "Upload a lockfile (package-lock.json, Cargo.lock, poetry.lock, Gemfile.lock, composer.lock) to see the tree.")
    else:
        lay = dgraph.layered_layout(gd, only_vulnerable=only)
        if len(lay["nodes"]) > 400:
            st.info("Graph is large; showing only chains to vulnerable packages is recommended.")
        ex, ey = [], []
        for a, b in lay["edges"]:
            ex += [lay["pos"][a][0], lay["pos"][b][0], None]
            ey += [lay["pos"][a][1], lay["pos"][b][1], None]
        fig = go.Figure(go.Scatter(x=ex, y=ey, mode="lines", line=dict(color="#B8B3A7", width=1), hoverinfo="skip", showlegend=False))
        for key, name, color in [("vuln", "Vulnerable", "#B42318"), ("direct", "Direct", "#0F766E"), ("trans", "Transitive", "#667085")]:
            ns = [n for n in lay["nodes"].values() if (key == "vuln" and n["vulnerable"]) or
                  (key == "direct" and n["direct"] and not n["vulnerable"]) or (key == "trans" and not n["direct"] and not n["vulnerable"])]
            if ns:
                fig.add_trace(go.Scatter(x=[lay["pos"][n["id"]][0] for n in ns], y=[lay["pos"][n["id"]][1] for n in ns], mode="markers+text",
                                         text=[f'{n["package"]}@{n["version"]}' for n in ns], textposition="top center", name=name,
                                         marker=dict(size=16, color=color), hovertext=[eco_label(n["ecosystem"]) for n in ns]))
        fig.update_layout(height=max(360, 90 * max((sum(1 for p in lay["pos"].values() if p[0] == d) for d in {p[0] for p in lay["pos"].values()}), default=1) + 160),
                          xaxis=dict(title="Dependency depth", dtick=1, showgrid=False), yaxis=dict(visible=False),
                          margin=dict(l=10, r=10, t=10, b=10), legend=dict(orientation="h"))
        st.plotly_chart(fig, width="stretch")

with t4:
    df = pd.DataFrame(r["packages"]).assign(status=lambda d: d["status"].map(LABEL))
    df["ecosystem"] = df["ecosystem"].map(eco_label)
    df["direct"] = df["direct"].map(ui.dep_label)
    c1, c2 = st.columns(2)
    pick = c1.multiselect("Filter by status", sorted(df["status"].unique()))
    lang = c2.multiselect("Filter by language", sorted(df["ecosystem"].unique()))
    view = df[df["status"].isin(pick)] if pick else df
    view = view[view["ecosystem"].isin(lang)] if lang else view
    st.dataframe(view.drop(columns=["purl"]), hide_index=True, width="stretch",
                 column_config={"advisories": st.column_config.NumberColumn("Advisories"), "recommended": "Suggested version",
                                "risk": st.column_config.NumberColumn("Top priority", format="%.0f")})

with t5:
    a, b = st.columns(2)
    sc = pd.DataFrame([(LABEL[k], s[k]) for k in LABEL if s[k]], columns=["Status", "Count"])
    cmap = {LABEL[k]: v[1] for k, v in ui.STATUS.items()}
    a.plotly_chart(px.pie(sc, names="Status", values="Count", hole=.55, color="Status", color_discrete_map=cmap,
                          title="Packages by check result"), width="stretch")
    if s["severity"]:
        sv = pd.DataFrame(list(s["severity"].items()), columns=["Severity", "Advisories"])
        b.plotly_chart(px.bar(sv, x="Severity", y="Advisories", title="Advisories by severity",
                              color_discrete_sequence=["#14212B"]), width="stretch")
    else:
        b.info("No advisories to chart.")
    if s.get("by_ecosystem"):
        eb = pd.DataFrame([(d["label"], d["total"] - d["vulnerable"], d["vulnerable"]) for d in s["by_ecosystem"].values()],
                          columns=["Language", "Not matched", "Vulnerable"])
        st.plotly_chart(px.bar(eb, x="Language", y=["Not matched", "Vulnerable"], title="Packages per language",
                               color_discrete_map={"Not matched": "#2F7D4F", "Vulnerable": "#B42318"}), width="stretch")

with t6:
    st.caption("Reports separate confirmed findings from incomplete checks.")
    c1, c2, c3 = st.columns(3)
    c1.download_button("Markdown report", to_markdown(r), "dependency-report.md", width="stretch")
    c2.download_button("CSV (packages)", to_csv(r), "dependency-report.csv", width="stretch")
    c3.download_button("JSON (full)", to_json(r), "dependency-report.json", width="stretch")
    d1, d2, d3 = st.columns(3)
    d1.download_button("SBOM (CycloneDX 1.5)", to_cyclonedx(r), "sbom.cdx.json", width="stretch",
                       help="Industry-standard software bill of materials with vulnerabilities and the dependency graph.")
    d2.download_button("SARIF (CI / GitHub)", to_sarif(r), "dependency-detective.sarif", width="stretch",
                       help="Upload to GitHub code scanning or any SARIF viewer.")
    d3.download_button("Fixed requirements.txt", to_fixed_requirements(r), "requirements.fixed.txt", width="stretch",
                       help="Python direct dependencies upgraded to verified fixed versions.")
    st.warning(r["disclaimer"])
