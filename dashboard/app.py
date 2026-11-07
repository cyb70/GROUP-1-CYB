"""Streamlit monitoring dashboard for the offline HIF-IDS simulation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from main import run_simulation  # noqa: E402

DATA = ROOT / "data"


def load_json(filename, default):
    path = DATA / filename
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def load_events():
    path = DATA / "events.jsonl"
    if not path.exists():
        return []
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


st.set_page_config(page_title="HIF-IDS Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ HIF-IDS Monitoring Dashboard")
st.caption("Hybrid Intelligent Firewall and Intrusion Detection System — offline simulation")

with st.sidebar:
    st.header("Simulation controls")
    st.warning("This dashboard operates on synthetic data. It does not modify your operating-system firewall.")
    if st.button("▶ Run simulation", type="primary", use_container_width=True):
        with st.spinner("Running the HIF-IDS simulation..."):
            try:
                run_simulation()
                st.success("Simulation completed.")
                st.rerun()
            except Exception as exc:  # show actionable failure rather than a blank page
                st.exception(exc)
    st.divider()
    st.caption("Run locally with: streamlit run dashboard/app.py")

summary = load_json("summary.json", {})
events = load_events()
incidents = load_json("incidents.json", [])
anomalies = load_json("rule_anomalies.json", [])

if not summary and not events:
    st.info("No simulation results found yet. Select **Run simulation** in the sidebar.")
    st.stop()

st.subheader("Simulation performance")
metrics = [
    ("Events processed", summary.get("events", 0)),
    ("Detection rate", f'{summary.get("detection_rate_percent", 0):.2f}%'),
    ("False-positive rate", f'{summary.get("false_positive_rate_percent", 0):.2f}%'),
    ("False-negative rate", f'{summary.get("false_negative_rate_percent", 0):.2f}%'),
    ("Raw IDS alerts", summary.get("raw_alert_count", 0)),
    ("Correlated notifications", summary.get("correlated_notification_count", 0)),
]
cols = st.columns(3)
for col, (label, value) in zip(cols * 2, metrics):
    col.metric(label, value)

st.subheader("Detection evaluation")
confusion = pd.DataFrame(
    {"Actual attack": [summary.get("TP", 0), summary.get("FN", 0)],
     "Actual normal": [summary.get("FP", 0), summary.get("TN", 0)]},
    index=["Detected", "Not detected"],
)
st.dataframe(confusion, use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("Alert correlation")
    st.metric("Notification reduction", f'{summary.get("notification_reduction_percent", 0):.2f}%')
    if incidents:
        incident_df = pd.DataFrame(incidents)
        st.bar_chart(incident_df.set_index("incident_id")["count"])
    else:
        st.info("No IDS incidents were generated.")
with right:
    st.subheader("Firewall rule analysis")
    st.metric("Potential rule findings", len(anomalies))
    if anomalies:
        st.dataframe(pd.DataFrame(anomalies), use_container_width=True, hide_index=True)
    else:
        st.success("No rule anomalies were identified in this policy.")

st.subheader("Security incidents")
if incidents:
    st.dataframe(pd.DataFrame(incidents), use_container_width=True, hide_index=True)
else:
    st.info("No incidents to display.")

st.subheader("Traffic and firewall decisions")
if events:
    rows = []
    for record in events:
        event = record.get("event", {})
        rows.append({
            "Event": event.get("event_id"),
            "Time": event.get("timestamp"),
            "Source IP": event.get("source_ip"),
            "Destination IP": event.get("destination_ip"),
            "Protocol": event.get("protocol"),
            "Port": event.get("destination_port"),
            "Firewall": record.get("firewall", {}).get("action"),
            "IDS alerts": len(record.get("alerts", [])),
            "Final decision": record.get("decision", {}).get("decision"),
            "Ground truth (evaluation only)": record.get("ground_truth_attack"),
        })
    event_df = pd.DataFrame(rows)
    decisions = ["All"] + sorted(event_df["Final decision"].dropna().unique().tolist())
    selected = st.selectbox("Filter by final decision", decisions)
    if selected != "All":
        event_df = event_df[event_df["Final decision"] == selected]
    st.dataframe(event_df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download event records (CSV)",
        event_df.to_csv(index=False).encode("utf-8"),
        file_name="hif_ids_events.csv",
        mime="text/csv",
    )
else:
    st.info("No traffic records found.")

st.caption("Prototype limitation: metrics are based on the synthetic labels generated for this experiment. They are not evidence of real-world detection performance.")
