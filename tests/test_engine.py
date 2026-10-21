import sys
import pytest
from pathlib import Path
# adding src dir to sys.path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.engine import LogNormalizer

# instantiate LogNormalizer
@pytest.fixture
def normalizer() -> LogNormalizer:
    return LogNormalizer()

# Test 1: JSON EVTX Log
def test_parse_json_etx(normalizer):
    sample_input = '{"EventID": 4688, "User": "CORP\\\\admin", "Process": "powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"}'
    result = normalizer.parse_line(sample_input)
    assert result["source_type"] == "evtx"
    assert result["event_id"] == "4688"
    assert result["process_name"] == "powershell.exe"
    assert "-enc" in  result["command_line"]

# Test 2: Key-Value EVTX Log
def test_parse_evtx_kv(normalizer):
    sample_input = '2026-10-20T12:00:00Z EventID=4688 User=admin SourceIP=10.0.0.5 Process=cmd.exe CommandLine="cmd.exe /c whoami"'
    result = normalizer.parse_line(sample_input)
    assert result["event_id"] == "4688"
    assert result["user"] == "admin"
    assert result["source_ip"] == "10.0.0.5"
    assert result["command_line"] == "cmd.exe /c whoami" # verifies quotes were stripped

# Test 3: Syslog SSH Failed Login
def test_parse_ssh_fail(normalizer):
    sample_input = 'Oct 20 14:22:01 bastion sshd[1234]: Failed password for invalid user root from 192.168.1.50 port 54321 ssh2'
    result = normalizer.parse_line(sample_input)
    assert result["source_type"] == "syslog"
    assert result["event_id"] == "SSH_AUTH_FAIL"
    assert result["user"] == "root"
    assert result["source_ip"] == "192.168.1.50"

# Test 4: Auditd Execve
def test_parse_auditd_execve(normalizer):
    sample_input = 'type=EXECVE msg=audit(1729425600.123:456): argc=3 a0="/bin/bash" a1="-c" a2="cat /etc/shadow"'
    result = normalizer.parse_line(sample_input)
    assert result["source_type"] == "auditd"
    assert result["event_id"] == "AUDITD_EXECVE"
    assert result["process_name"] == "/bin/bash"
    assert result["command_line"] == "/bin/bash -c cat /etc/shadow"

# Test 5: Web Access Log
def test_parse_web_log(normalizer):
    sample_input = '203.0.113.99 - frank [20/Oct/2026:13:55:36 +0000] "GET /login.php?user=admin\' OR 1=1-- HTTP/1.1" 403 1024'
    result = normalizer.parse_line(sample_input)
    assert result["source_type"] == "web"
    assert result["event_id"] == "WEB_ATTACK"
    assert result["source_ip"] == "203.0.113.99"
    assert result["action"] == "http_403"

# Test 6: Batch Parsing and Empty Lines
def test_parse_batch(normalizer):
    sample_list = [
        '2026-10-20T12:00:00Z EventID=4688 User=admin SourceIP=10.0.0.5 Process=cmd.exe CommandLine="cmd.exe /c whoami"',
        '203.0.113.99 - frank [20/Oct/2026:13:55:36 +0000] "GET /login.php?user=admin\' OR 1=1-- HTTP/1.1" 403 1024',
        ""
    ]
    result = normalizer.parse_batch(sample_list)
    assert len(result) == 2
