from datetime import datetime, timezone
from typing import Any, Dict, List
from pydantic import BaseModel, Field
import json
import re

class NormalizedLog(BaseModel):
    timestamp: str = (Field(default_factory=lambda: datetime.now(timezone.utc).isoformat()))
    source_type: str = "unknown" # e.g. 'evtx', 'syslog', 'auditd', web'
    event_id: str = "DEFAULT"
    source_ip: str = "local"
    user: str = "unknown"
    process_name: str = "unknown"
    command_line: str = ""
    action: str = "unknown"
    raw_event: str = ""

    # helper mapping method
    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

class LogNormalizer:
    EVTX_KV_RE: Dict[str, re.Pattern] = {
        "timestamp": re.compile(r"^(?P<val>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"),
        "event_id": re.compile(r"(?i)EventID=(?P<val>\d+)"),
        "user": re.compile(r"(?i)User=(?P<val>[^\s]+)"),
        "source_ip": re.compile(r"(?i)SourceIP=(?P<val>[^\s]+)"),
        "process_name": re.compile(r"(?i)Process=(?P<val>[^\s]+)"),
        "command_line": re.compile(r'(?i)CommandLine=(?:"(?P<quoted>[^"]+)"|(?P<unquoted>[^\s]+))')
    }
    SSH_FAIL_RE: re.Pattern = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
    )
    SUDO_RE: re.Pattern = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo(?:\[\d+\])?:\s+"
    r"(?P<user>\S+)\s+:.*COMMAND=(?P<command_line>.+)$"
    )
    WEB_RE: re.Pattern = re.compile(
    r'^(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<command_line>(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+[^"]+)"\s+(?P<status>\d{3})'
    )
    AUDITD_RE: re.Pattern = re.compile(
        r"type=EXECVE\s+msg=audit\((?P<timestamp>\d+\.\d+):\d+\):\s+argc=\d+\s+(?P<args>.*)"
    )

    # parsing logic (line and batch methods)
    def parse_line(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        if not line:
            return NormalizedLog(raw_event=raw_line).to_dict()
        
        # Check 1: JSON input
        if line.startswith("{"):
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    return NormalizedLog(
                        timestamp=str(data.get("timestamp") or data.get("TimeCreated") or datetime.now(timezone.utc).isoformat()),
                        source_type=str(data.get("source_type", "evtx")),
                        event_id=str(data.get("event_id") or data.get("EventID") or "DEFAULT"),
                        source_ip=str(data.get("source_ip") or data.get("SourceIP") or "local"),
                        user=str(data.get("user") or data.get("User") or "unknown"),
                        process_name=str(data.get("process_name") or data.get("Process") or "unknown"),
                        command_line=str(data.get("command_line") or data.get("CommandLine") or ""),
                        action=str(data.get("action", "json_event")),
                        raw_event=line,
                    ).to_dict()
            except json.JSONDecodeError:
                pass

        # Check 2: Windows EVTX Key-Value
        if "eventid=" in line.lower():
            extracted: Dict[str, str] = {}
            for key, pattern in self.EVTX_KV_RE.items():
                match = pattern.search(line)
                if match:
                    # handles command line key name
                    if key == "command_line":
                        extracted[key] = match.group("quoted") or match.group("unquoted") or ""
                    else:
                        extracted[key] = match.group("val")

            return NormalizedLog(
                source_type="evtx",
                action="windows_event",
                raw_event=line,
                **extracted,
            ).to_dict()

        # Check 3: Syslog SSH Failed Login
        if match := self.SSH_FAIL_RE.search(line):
            return NormalizedLog(
                source_type="syslog",
                event_id="SSH_AUTH_FAIL",
                process_name="sshd",
                action="login_failed",
                raw_event=line,
                **match.groupdict()
            ).to_dict()

        # Check 4: Privilege Escalation
        if match := self.SUDO_RE.search(line):
            return NormalizedLog(
                source_type="syslog",
                event_id="SUDO_EXEC",
                process_name="sudo",
                action="privilege_escalation",
                raw_event=line,
                **match.groupdict()
            ).to_dict()

        # Check 5: Auditd Exec
        if match := self.AUDITD_RE.search(line):
            raw_args = match.group("args") # grabs arg string
            arg_list = re.findall(r'a\d+="([^"]+)"', raw_args) # extracts quoted
            cmd_line = " ".join(arg_list) if arg_list else raw_args.strip() # clean cmd line
            proc_name = arg_list[0] if arg_list else "auditd"

            return NormalizedLog(
                timestamp=match.group("timestamp"),
                source_type="auditd",
                event_id="AUDITD_EXECVE",
                process_name=proc_name,
                command_line=cmd_line,
                action="execve",
                raw_event=line
            ).to_dict()

        # Check 6: Web Server Access Log
        if match := self.WEB_RE.search(line):
            groups = match.groupdict()
            status = groups.pop("status", "200")
            return NormalizedLog(
                source_type="web",
                event_id="WEB_ATTACK",
                process_name="http_server",
                action=f"http_{status}",
                raw_event=line,
                **groups
            ).to_dict()

        # fallback
        return NormalizedLog(raw_event=line).to_dict()

    def parse_batch(self, raw_lines: List[str]) -> List[Dict[str, Any]]:
        return [self.parse_line(line) for line in raw_lines if line and line.strip()]