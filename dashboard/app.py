import json
from pathlib import Path
import pandas as pd
import streamlit as st
from analyzer.parser import parse_events
from analyzer.detector import detect

st.set_page_config(page_title="Windows Event Log Analyzer", page_icon="🛡️", layout="wide")
st.title("🛡️ Windows Event Log Analyzer")
st.caption("Defensive Windows Security log triage | SOC portfolio project")
upload=st.file_uploader("Upload events.json",type=["json"])
raw=json.load(upload) if upload else json.loads(Path("sample_logs/sample_events.json").read_text(encoding="utf-8"))
events=parse_events(raw); alerts=detect(events); df=pd.DataFrame(events)
c1,c2,c3=st.columns(3)
c1.metric("Events analyzed",len(events)); c2.metric("Alerts",len(alerts))
c3.metric("High severity",sum(a["severity"]=="HIGH" for a in alerts))
st.subheader("Event distribution")
if not df.empty:
    st.bar_chart(df["event_id"].value_counts().sort_index())
    st.dataframe(df,use_container_width=True,hide_index=True)
st.subheader("Detection alerts")
if alerts:
    st.dataframe(pd.DataFrame(alerts),use_container_width=True,hide_index=True)
    st.download_button("Download alerts.json",json.dumps(alerts,indent=2),
                       file_name="alerts.json",mime="application/json")
else: st.success("No configured detection rules triggered.")
st.info("Included sample data is synthetic. Alerts are leads for investigation, not proof of compromise.")
