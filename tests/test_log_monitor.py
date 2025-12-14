"""Tests for log monitor agent."""

import pytest
from pathlib import Path
import tempfile
import os

from agents.log_monitor import LogMonitorAgent, LogParser


@pytest.fixture
def sample_log_file():
    """Create sample log file."""
    temp_dir = tempfile.mkdtemp()
    log_file = Path(temp_dir) / "test.log"
    log_file.write_text(
        "Jan 15 10:23:45 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.100\n"
        "Jan 15 10:25:30 server1 apache2[2001]: 192.168.1.50 - - [15/Jan/2024:10:25:30 +0000] \"GET /index.php?id=1' OR '1'='1 HTTP/1.1\" 200 1234\n"
    )
    yield log_file
    os.remove(log_file)
    os.rmdir(temp_dir)


@pytest.fixture
def log_monitor(sample_log_file):
    """Create log monitor agent."""
    return LogMonitorAgent(
        log_paths=[str(sample_log_file.parent)],
        anomaly_threshold=0.7,
    )


def test_log_parser_syslog():
    """Test syslog parsing."""
    line = "Jan 15 10:23:45 server1 sshd[1234]: Failed password for invalid user admin"
    result = LogParser.parse_syslog(line)
    assert result is not None
    assert "sshd" in result["service"]
    assert "Failed password" in result["message"]


def test_log_parser_apache():
    """Test Apache log parsing."""
    line = '192.168.1.50 - - [15/Jan/2024:10:25:30 +0000] "GET /index.php?id=1 HTTP/1.1" 200 1234'
    result = LogParser.parse_apache(line)
    assert result is not None
    assert result["ip"] == "192.168.1.50"
    assert result["status"] == 200


def test_detect_attack_patterns():
    """Test attack pattern detection."""
    log_entry = {
        "message": "GET /index.php?id=1' OR '1'='1 HTTP/1.1",
        "raw": "GET /index.php?id=1' OR '1'='1 HTTP/1.1",
    }
    patterns = LogParser.detect_attack_patterns(log_entry)
    assert "SQL_INJECTION" in patterns


@pytest.mark.asyncio
async def test_analyze_logs(log_monitor, sample_log_file):
    """Test log analysis."""
    alerts = await log_monitor.analyze_logs(sample_log_file, max_lines=10)
    assert isinstance(alerts, list)
    # Should detect SQL injection in the sample log
    sql_alerts = [a for a in alerts if "SQL" in str(a.get("attack_patterns", []))]
    assert len(sql_alerts) > 0

