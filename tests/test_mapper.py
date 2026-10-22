import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from src.engine import LogNormalizer
from src.mapper import FrameworkMapper

@pytest.fixture
def mapper() -> FrameworkMapper:
    return FrameworkMapper()

@pytest.fixture
def normalizer() -> LogNormalizer:
    return LogNormalizer()

# Test 1: cmd.exe Process Creation
def test_map_4688_cmd(mapper):
    sample_event = {"event_id": "4688", "process_name": "cmd.exe", "command_line": "cmd.exe /c dir"}
    result = mapper.enrich_event(sample_event)
    assert result["mitre_mapping"]["tactic"] == "Execution"
    assert result["mitre_mapping"]["technique_id"] == "T1059.003"
    assert result["nist_csf_mapping"]["function"] == "Detect"
    assert result["nist_csf_mapping"]["subcategory"] == "DE.CM-09"

# Test 2: Encoded PowerShell
def test_map_4688_powershell_enc(mapper):
    sample_event = {"event_id": "4688", "process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"}
    result = mapper.enrich_event(sample_event)
    assert result["mitre_mapping"]["technique_id"] == "T1059.001"
    assert "PowerShell" in result["mitre_mapping"]["technique_name"]

# Test 3: Event with Empty 'patterns' List
def test_map_1102_audit_log_cleared(mapper):
    sample_event = {"event_id": "1102"}
    result = mapper.enrich_event(sample_event)
    assert result["mitre_mapping"]["tactic"] == "Defense Evasion"
    assert result["mitre_mapping"]["technique_id"] == "T1070.001"
    assert result["nist_csf_mapping"]["function"] == "Govern"
    assert result["nist_csf_mapping"]["subcategory"] == "GV.OV-03"

# Test 4: Unknown Event ID Fallback
def test_map_unknown_event_fallback(mapper):
    sample_event = {"event_id": "9999"}
    result = mapper.enrich_event(sample_event)
    assert result["mitre_mapping"]["technique_id"] == "T1082"
    assert result["nist_csf_mapping"]["subcategory"] == "DE.AE-02"

# Test 5: End-to-End Batch Pipeline
def test_end_to_end_batch(normalizer, mapper):
    raw_logs = [
        "Oct 20 14:22:01 bastion sshd[1234]: Failed password for invalid user admin from 10.10.10.5 port 22 ssh2",
        '203.0.113.5 - - [20/Oct/2026:14:00:00 +0000] "GET /uploads/shell.php HTTP/1.1" 200 512'
    ]

    # step 1: normalize raw log strings into structured dicts
    parsed_events = normalizer.parse_batch(raw_logs)

    # step 2: enrich normalized dicts with mappings
    enriched_events = mapper.enrich_batch(parsed_events)

    assert len(enriched_events) == 2

    # verify log 1 (ssh invalid user > T1110.003 Password Spraying + DE.CM-03)
    assert enriched_events[0]["event_id"] == "SSH_AUTH_FAIL"
    assert enriched_events[0]["mitre_mapping"]["technique_id"] == "T1110.003"
    assert enriched_events[0]["nist_csf_mapping"]["subcategory"] == "DE.CM-03"

    # verify log 2 (web shell > T1505.003 Web Shell + DE.CM-01)
    assert enriched_events[1]["event_id"] == "WEB_ATTACK"
    assert enriched_events[1]["mitre_mapping"]["technique_id"] == "T1505.003"
    assert enriched_events[1]["nist_csf_mapping"]["subcategory"] == "DE.CM-01"