# LogBridge Framework

**A Dual-Mode Cybersecurity Logging & Telemetry Enrichment Pipeline (MITRE ATT&CK v20 + NIST CSF 2.0)**

`LogBridge Framework` is a **"Write Once, Ingest Anywhere"** cybersecurity logging pipeline that decouples multi-source log normalization, dual-framework enrichment (**MITRE ATT&CK v20** operational detection + **NIST CSF 2.0** governance posture), and output visualization/SIEM forwarding.

---

## 1. High-Level Dual-Mode Architecture

```text
[ Log Sources ] (Windows EVTX, Linux Syslog, Web Access, Linux Auditd)
       │
       ▼
[ Core Ingestion & Parsing Engine ] (src/engine.py — Python / Regex / JSON)
       │
       ▼
[ Dual-Framework Enrichment Layer ] (src/mapper.py — MITRE ATT&CK v20 + NIST CSF 2.0)
       │
       ├─────────────────────────────────────────┐
       ▼                                         ▼
[ Standalone Engine Mode ]              [ SIEM Forwarder Mode ]
  • Local SQLite Persistence              • Splunk HTTP Event Collector (HEC)
  • Streamlit Executive Dashboard         • Microsoft Sentinel (Syslog CEF)
  • NIST CSF 2.0 & ATT&CK Heatmaps        • Elastic Stack / Logstash (NDJSON)
```

* **Standalone Mode:** Ingests raw logs (JSON, Key-Value EVTX, Syslog, Auditd, and HTTP access logs), normalizes fields into a unified Pydantic schema, enriches events with MITRE ATT&CK and NIST CSF 2.0 metadata, persists state in SQLite, and presents live telemetry gauges and heatmaps via a Streamlit Executive Dashboard.
* **SIEM Integrated Mode:** Formats and forwards the exact same enriched telemetry into enterprise SIEM formats, including **Splunk HEC JSON envelopes**, **Microsoft Sentinel Common Event Format (CEF)**, and **Elastic Stack / Logstash bulk NDJSON**.

---

## 2. Dual-Framework Mapping Matrix

Every normalized log event is enriched with both **operational adversary tactics/techniques** and **governance/compliance outcomes**:

| Log Source | Event / Signature | MITRE ATT&CK v20 Technique | NIST CSF 2.0 Subcategory |
| :--- | :--- | :--- | :--- |
| **Windows EVTX** | `4688` (`powershell.exe -enc`) | `T1059.001` — PowerShell | `DE.CM-09` (Runtime & Software Monitoring) |
| **Windows EVTX** | `4688` (`cmd.exe`) | `T1059.003` — Windows Command Shell | `DE.CM-09` (Runtime & Software Monitoring) |
| **Windows EVTX** | `4688` (`rundll32 ... lsass`) | `T1003.001` — LSASS Memory Dumping | `DE.CM-09` (Runtime & Software Monitoring) |
| **Windows EVTX** | `4625` (`LogonType=3/10`) | `T1110.001` — Password Guessing | `DE.CM-03` (Personnel & Auth Activity Monitoring) |
| **Windows EVTX** | `4624` (`LogonType=10`) | `T1021.001` — Remote Desktop Protocol | `PR.AA-03` (User & Service Authentication) |
| **Windows EVTX** | `1102` (Audit Log Cleared) | `T1070.001` — Clear Windows Event Logs | `GV.OV-03` (Risk Management & Audit Oversight) |
| **Windows EVTX** | `7045` (Service Installed) | `T1543.003` — Windows Service Persistence | `DE.AE-03` (Unauthorized Change Correlation) |
| **Windows EVTX** | `4720` (Local Account Created) | `T1136.001` — Create Local Account | `PR.AA-01` (Identity & Credential Management) |
| **Linux Syslog** | `SSH_AUTH_FAIL` (`invalid user`) | `T1110.003` — Password Spraying | `DE.CM-03` (Personnel & Auth Activity Monitoring) |
| **Linux Syslog** | `SUDO_EXEC` (`COMMAND=...`) | `T1548.003` — Sudo & Sudo Caching | `PR.AA-05` (Access Permissions & Least Privilege) |
| **Linux Auditd** | `AUDITD_EXECVE` (`/bin/bash`, `nc`) | `T1059.004` — Unix Shell | `DE.CM-09` (Runtime & Software Monitoring) |
| **Web Access** | `WEB_ATTACK` (`UNION SELECT`) | `T1190` — Exploit Public-Facing App | `DE.CM-01` (Network & Service Monitoring) |
| **Web Access** | `WEB_ATTACK` (`shell.php`, `c99.php`) | `T1505.003` — Web Shell | `DE.CM-01` (Network & Service Monitoring) |

### Example Enriched Event Output

```json
{
  "timestamp": "2026-10-20T12:00:00Z",
  "source_type": "evtx",
  "event_id": "4688",
  "source_ip": "10.0.0.5",
  "user": "admin",
  "process_name": "cmd.exe",
  "command_line": "cmd.exe /c whoami",
  "action": "windows_event",
  "mitre_mapping": {
    "tactic": "Execution",
    "technique_id": "T1059.003",
    "technique_name": "Command and Scripting Interpreter: Windows Command Shell"
  },
  "nist_csf_mapping": {
    "function": "Detect",
    "category": "DE.CM",
    "subcategory": "DE.CM-09",
    "description": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events"
  }
}
```

---

## 3. Repository Structure

```text
LogBridge-Framework/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── docker-compose.yml
├── mappings/
│   ├── mitre_attck_map.json       # Event IDs & Regex -> MITRE ATT&CK v20 Tactics/Techniques
│   └── nist_csf_map.json          # Detection signatures -> NIST CSF 2.0 Subcategories
├── sample_telemetry/
│   ├── windows_evtx.json          # Sample Windows EVTX intrusion chain (JSONL)
│   ├── linux_syslog_auditd.log    # Sample Linux SSH, sudo, and auditd EXECVE logs
│   └── mixed_attack_campaign.log  # Multi-stage kill chain across Web, Linux, and Windows
├── src/
│   ├── __init__.py
│   ├── app.py                     # Standalone Streamlit Executive Dashboard
│   ├── engine.py                  # Core log ingestion, parsing & Pydantic normalization
│   ├── mapper.py                  # Dual-framework enrichment engine
│   └── siem_connectors.py         # Local SQLite storage & SIEM exporters (Splunk, Sentinel, Elastic)
└── tests/
    ├── test_engine.py             # Unit tests for multi-format log normalization
    └── test_mapper.py             # Unit tests for MITRE ATT&CK & NIST CSF 2.0 enrichment
```

---

## 4. Quickstart & Deployment

### Option 1: Local Python Environment

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the Standalone Streamlit Executive Dashboard
streamlit run src/app.py
```

### Option 2: Docker Compose

```bash
docker compose up -d
```
Then open `http://localhost:8501` in your browser.

---

## 5. Sample Telemetry & Automated Tests

### Loading Sample Telemetry in the Dashboard
1. Click **Load Sample Telemetry** in the left sidebar for instant built-in telemetry, **or**
2. Upload any file from `sample_telemetry/` (`windows_evtx.json`, `linux_syslog_auditd.log`, or `mixed_attack_campaign.log`) using the sidebar file uploader and click **Ingest & Enrich Custom Logs**.

### Running Unit Tests
```bash
python -m pytest -v
```

---

## 6. License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for more information.

