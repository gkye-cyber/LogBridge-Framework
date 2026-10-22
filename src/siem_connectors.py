import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests

class SQLiteStorage:
    def __init__(self, db_path: str = "logbridge.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS enriched_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_type TEXT,
                event_id TEXT,
                source_ip TEXT,
                user TEXT,
                tactic TEXT,
                technique_id TEXT,
                nist_function TEXT,
                nist_subcategory TEXT,
                full_json TEXT
                )
                """
            )

    def insert_batch(self, enriched_events: List[Dict[str, Any]]) -> int:
        if not enriched_events:
            return 0

        rows = []
        for event in enriched_events:
            mitre = event.get("mitre_mapping", {})
            nist = event.get("nist_csf_mapping", {})
            rows.append((
                event.get("timestamp", ""),
                event.get("source_type", "unknown"),
                event.get("event_id", "DEFAULT"),
                event.get("source_ip", "local"),
                event.get("user", "unknown"),
                mitre.get("tactic", ""),
                mitre.get("technique_id", ""),
                nist.get("function", ""),
                nist.get("subcategory", ""),
                json.dumps(event)
            ))

        with sqlite3.connect(self.db_path) as conn:
            # '?' placeholders=fast performance and prevents SQLi
            conn.executemany(
                """
                INSERT INTO enriched_logs (
                    timestamp, source_type, event_id, source_ip, user, 
                    tactic, technique_id, nist_function, nist_subcategory,
                    full_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows
            )
        return len(rows)

    # load stored events back into streamlit dashboard
    def fetch_all(self, limit: int = 500) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT full_json FROM enriched_logs ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            return [json.loads(row[0]) for row in cursor.fetchall()]

    # 'Clear Database" button
    def clear_all(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM enriched_logs")

# SIEM SUPPORT: Splunk, Micrsoft Sentinel, & Elastic Stack/Logstash
class SIEMExporter:
    def format_splunk_hec(
            self,
            enriched_event: Dict[str, Any],
            index: str = "main",
            sourcetype: str = "logbridge:enriched"
    ) -> Dict[str, Any]:
        return {
            "time": time.time(),
            "host": enriched_event.get("source_ip", "local"),
            "source": f"logbridge:{enriched_event.get('source_type', 'unknown')}",
            "sourcetype": sourcetype,
            "index": index,
            "event": enriched_event
        }

    # pipe-delimited headers followed by 'key=value' extensions
    def format_sentinel_cef(self, enriched_event: Dict[str, Any]) -> str:
        mitre = enriched_event.get("mitre_mapping", {})
        nist = enriched_event.get("nist_csf_mapping", {})
        event_id = enriched_event.get("event_id", "DEFAULT")
        tech_name = mitre.get("technique_name", "Unknown Technique")
        tech_id = mitre.get("technique_id", "T0000")
        tactic = mitre.get("tactic", "Unknown")
        nist_sub = nist.get("subcategory", "DE.AE-02")

        return (
            f"CEF:0|LogBridge|DualFramework|1.0|{event_id}|{tech_name}|5|"
            f"src={enriched_event.get('source_ip', 'local')} "
            f"suser={enriched_event.get('user', 'unknown')} "
            f"sproc={enriched_event.get('process_name', 'unknown')} "
            f"cs1Label=MITRE_TECHNIQUE cs1={tech_id} "
            f"cs2Label=MITRE_TACTIC cs2={tactic} "
            f"cs3Label=NIST_CSF_2_0 cs3={nist_sub} "
            f"msg={enriched_event.get('command_line', '')}"
        )

    def format_elastic_ndjson(self, enriched_events: List[Dict[str, Any]]) -> str:
        return "\n".join(json.dumps(event) for event in enriched_events)

    # splunk outbound forwarder w/ 'dry run' mode
    def send_to_splunk_hec(
            self,
            enriched_events: List[Dict[str, Any]],
            hec_url: str= "https://localhost:8008/services/collector/event",
            hec_token: str = "00000000-0000-0000-0000-000000000000",
            dry_run: bool = True
    ) -> Dict[str, Any]:
        payloads = [self.format_splunk_hec(e) for e in enriched_events]
        if dry_run or not payloads:
            return {
                "status": "dry_run_success",
                "events_prepared": len(payloads),
                "sample_payload": payloads[0] if payloads else None
            }

        body = "\n".join(json.dumps(p) for p in payloads)
        headers = {"Authorization": f"Splunk {hec_token}"}
        try:
            response = requests.post(hec_url, headers=headers, data=body, timeout=10, verify=False)
            return {
                "status": "sent" if response.ok else "error",
                "status_code": response.status_code,
                "events_prepared": len(payloads),
                "response_text": response.text
            }
        except requests.RequestException as exec:
            return {
                "status": "error",
                "error": str(exec)
            }