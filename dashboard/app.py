import json
from pathlib import Path

import pandas as pd
import streamlit as st

from analyzer.parser import parse_events
from analyzer.detector import detect

st.set_page_config(
    page_title="Windows Event Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
    .main-title {font-size: 2rem; font-weight: 750; margin-bottom: 0.15rem;}
    .subtitle {color: #9ca3af; margin-bottom: 1.2rem;}
    .alert-card {
        border: 1px solid rgba(255,255,255,.12);
        border-left: 5px solid #64748b;
        border-radius: 9px;
        padding: 13px 16px;
        margin: 8px 0;
        background: rgba(255,255,255,.035);
    }
    .alert-high {border-left-color: #ef4444;}
    .alert-medium {border-left-color: #f59e0b;}
    .alert-low {border-left-color: #3b82f6;}
    .muted {color: #9ca3af; font-size: .88rem;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-title">🛡️ Windows Event Log Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">SOC investigation workspace · Windows Security event monitoring</div>', unsafe_allow_html=True)

uploaded = st.file_uploader("Upload Windows event export (JSON)", type=["json"])
if uploaded:
    try:
        raw_events = json.load(uploaded)
        if not isinstance(raw_events, list):
            st.error("Invalid file: expected a JSON list of event records.")
            st.stop()
        data_source = f"Uploaded file: {uploaded.name}"
    except (json.JSONDecodeError, UnicodeDecodeError):
        st.error("Could not read this JSON file. Please upload a valid events.json export.")
        st.stop()
else:
    sample_path = Path("sample_logs/sample_events.json")
    if not sample_path.exists():
        st.error("Sample file not found. Run the app from the project root folder.")
        st.stop()
    raw_events = json.loads(sample_path.read_text(encoding="utf-8"))
    data_source = "Built-in synthetic sample data"

events = parse_events(raw_events)
alerts = detect(events)
df = pd.DataFrame(events)
alerts_df = pd.DataFrame(alerts)

st.caption(f"Data source: {data_source} · Sample records are synthetic, not real attack evidence.")

total_events = len(events)
high_count = sum(a.get("severity") == "HIGH" for a in alerts)
medium_count = sum(a.get("severity") == "MEDIUM" for a in alerts)
failed_count = sum(int(e.get("event_id", 0)) == 4625 for e in events)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Events analyzed", total_events)
m2.metric("Total alerts", len(alerts))
m3.metric("High severity", high_count)
m4.metric("Failed logons", failed_count)

st.divider()

left, right = st.columns([1.05, 1])
with left:
    st.subheader("Event distribution")
    if not df.empty:
        distribution = df["event_id"].value_counts().sort_index()
        st.bar_chart(distribution)
    else:
        st.info("No events available to chart.")

with right:
    st.subheader("Alert severity")
    if alerts:
        severity_counts = pd.Series([a["severity"] for a in alerts]).value_counts()
        st.bar_chart(severity_counts)
    else:
        st.info("No alerts generated.")

st.divider()
st.subheader("Event explorer")

if not df.empty:
    event_ids = sorted(df["event_id"].dropna().astype(int).unique().tolist())
    usernames = sorted({str(x) for x in df.get("username", pd.Series(dtype=str)).dropna() if str(x).strip()})
    ips = sorted({str(x) for x in df.get("source_ip", pd.Series(dtype=str)).dropna() if str(x).strip()})

    f1, f2, f3 = st.columns(3)
    with f1:
        selected_ids = st.multiselect("Filter by Event ID", event_ids, default=event_ids)
    with f2:
        selected_users = st.multiselect("Filter by username", usernames, default=usernames)
    with f3:
        selected_ips = st.multiselect("Filter by source IP", ips, default=ips)

    search_text = st.text_input("Search events", placeholder="Search username, IP, event ID, computer...")
    filtered = df.copy()
    filtered = filtered[filtered["event_id"].isin(selected_ids)]
    if "username" in filtered.columns and selected_users:
        filtered = filtered[filtered["username"].fillna("").astype(str).isin(selected_users)]
    elif not selected_users:
        filtered = filtered.iloc[0:0]
    if "source_ip" in filtered.columns and selected_ips:
        filtered = filtered[filtered["source_ip"].fillna("").astype(str).isin(selected_ips)]
    elif not selected_ips:
        filtered = filtered.iloc[0:0]
    if search_text.strip():
        mask = filtered.astype(str).apply(
            lambda col: col.str.contains(search_text.strip(), case=False, na=False)
        ).any(axis=1)
        filtered = filtered[mask]

    st.caption(f"Showing {len(filtered)} of {len(df)} events")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇️ Download filtered events (CSV)",
        filtered.to_csv(index=False).encode("utf-8"),
        file_name="filtered_windows_events.csv",
        mime="text/csv",
    )
else:
    st.info("No events available.")

st.divider()
st.subheader("Detection alerts")

if alerts:
    if not alerts_df.empty:
        a1, a2 = st.columns(2)
        with a1:
            severity_filter = st.multiselect(
                "Filter alert severity",
                ["HIGH", "MEDIUM", "LOW"],
                default=["HIGH", "MEDIUM", "LOW"],
            )
        with a2:
            alert_search = st.text_input("Search alerts", placeholder="Search rule, username, IP...")
        visible_alerts = alerts_df[alerts_df["severity"].isin(severity_filter)]
        if alert_search.strip():
            alert_mask = visible_alerts.astype(str).apply(
                lambda col: col.str.contains(alert_search.strip(), case=False, na=False)
            ).any(axis=1)
            visible_alerts = visible_alerts[alert_mask]

        for _, alert in visible_alerts.iterrows():
            severity = str(alert.get("severity", "LOW")).lower()
            st.markdown(
                f"""
                <div class="alert-card alert-{severity}">
                    <strong>{str(alert.get('severity', ''))} · {str(alert.get('title', 'Alert'))}</strong><br>
                    <span class="muted">Rule: {str(alert.get('rule', ''))} · Event ID: {str(alert.get('event_id', ''))}</span><br>
                    <span>{str(alert.get('recommendation', 'Review this event and surrounding activity.'))}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.dataframe(visible_alerts, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Download alerts (JSON)",
            json.dumps(visible_alerts.to_dict(orient="records"), indent=2),
            file_name="windows_security_alerts.json",
            mime="application/json",
        )
        st.download_button(
            "⬇️ Download alerts (CSV)",
            visible_alerts.to_csv(index=False).encode("utf-8"),
            file_name="windows_security_alerts.csv",
            mime="text/csv",
        )
    else:
        st.info("No alerts match the selected filters.")
else:
    st.success("No configured detection rules triggered.")

st.divider()
st.subheader("MITRE ATT&CK reference")
mitre_map = {
    "POSSIBLE_BRUTE_FORCE": ("T1110", "Brute Force"),
    "SECURITY_AUDIT_LOG_CLEARED": ("T1070.001", "Clear Windows Event Logs"),
}
mapped = []
for alert in alerts:
    mapping = mitre_map.get(alert.get("rule"))
    if mapping:
        mapped.append({
            "Detection": alert.get("title", ""),
            "Technique ID": mapping[0],
            "Technique": mapping[1],
            "Reference": "Potential mapping; validate against investigation context."
        })
if mapped:
    st.dataframe(pd.DataFrame(mapped), use_container_width=True, hide_index=True)
else:
    st.caption("No current alert has an explicit ATT&CK reference in this prototype.")

st.info("Detection alerts are triage leads, not proof of compromise. Validate findings with event details, endpoint context, and authorized user activity.")
