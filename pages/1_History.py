"""Scan history and before/after comparison."""
import pandas as pd
import streamlit as st
from backend.core.compare import diff_reports
from backend.utils import db
from components import ui

ui.setup("Scan history")
st.title("Scan history")
st.caption("Stored in a local SQLite file. On Streamlit Community Cloud it resets when the app restarts.")

scans = db.list_scans()
if not scans:
    st.info("No scans yet. Run a scan on the home page first.")
    st.stop()

st.dataframe(pd.DataFrame(scans).rename(columns={"scanned_at": "Scanned (UTC)", "confirmed": "Confirmed matches"}),
             hide_index=True, width="stretch")

st.subheader("Compare two scans")
ids = [s["id"] for s in scans]
c1, c2 = st.columns(2)
old = c1.selectbox("Earlier scan", ids, index=min(1, len(ids) - 1))
new = c2.selectbox("Later scan", ids, index=0)
if st.button("Compare", type="primary"):
    d = diff_reports(db.get_scan(old), db.get_scan(new))
    for title, key in [("Newly introduced", "new"), ("Resolved", "resolved"), ("Still present", "persisting")]:
        st.markdown(f"**{title}: {len(d[key])}**")
        if d[key]:
            st.dataframe(pd.DataFrame(d[key], columns=["Ecosystem", "Package", "Version", "Advisory"]), hide_index=True, width="stretch")
