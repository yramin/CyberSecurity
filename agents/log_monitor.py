"""
Log Monitor Agent for real-time log analysis and threat detection.
Supports syslog, Apache, nginx, and Windows Event logs.
"""

import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

import numpy as np
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core.llm_client import LLMClient
from core.rag_engine import RAGEngine

logger = logging.getLogger(__name__)


class LogParser:
    """Parser for different log formats."""

    # Common attack patterns
    ATTACK_PATTERNS = {
        "SQL_INJECTION": [
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)",
            r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')",
            r"(?i)(exec\s*\(|execute\s*\()",
        ],
        "XSS_ATTACK": [
            r"(?i)(<script|javascript:|onerror=|onload=)",
            r"(?i)(alert\s*\(|document\.cookie)",
        ],
        "BRUTE_FORCE": [
            r"(?i)(failed\s+password|authentication\s+failure|invalid\s+user)",
            r"(?i)(401|403).*multiple",
        ],
        "UNAUTHORIZED_ACCESS": [
            r"(?i)(unauthorized|forbidden|access\s+denied)",
            r"(?i)(401|403|404).*admin|root|sudo",
        ],
        "MALWARE_SIGNATURE": [
            r"(?i)(cmd\.exe|powershell|wscript|cscript)",
            r"(?i)(\.exe|\.bat|\.ps1).*download|fetch",
        ],
    }

    @staticmethod
    def parse_syslog(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse syslog format.

        Args:
            line: Log line

        Returns:
            Parsed log entry or None
        """
        # Syslog format: timestamp hostname service: message
        pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)"
        match = re.match(pattern, line)
        if match:
            return {
                "timestamp": match.group(1),
                "hostname": match.group(2),
                "service": match.group(3),
                "message": match.group(4),
                "raw": line,
            }
        return None

    @staticmethod
    def parse_apache(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse Apache access log format.

        Args:
            line: Log line

        Returns:
            Parsed log entry or None
        """
        # Apache Common Log Format: IP - - [timestamp] "method path protocol" status size
        pattern = r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)'
        match = re.match(pattern, line)
        if match:
            return {
                "ip": match.group(1),
                "timestamp": match.group(4),
                "method": match.group(5),
                "path": match.group(6),
                "protocol": match.group(7),
                "status": int(match.group(8)),
                "size": match.group(9),
                "raw": line,
            }
        return None

    @staticmethod
    def parse_nginx(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse nginx access log format.

        Args:
            line: Log line

        Returns:
            Parsed log entry or None
        """
        # Similar to Apache, nginx uses similar format
        return LogParser.parse_apache(line)

    @staticmethod
    def detect_attack_patterns(log_entry: Dict[str, Any]) -> List[str]:
        """
        Detect attack patterns in log entry.

        Args:
            log_entry: Parsed log entry

        Returns:
            List of detected attack types
        """
        detected = []
        message = log_entry.get("message", log_entry.get("raw", ""))

        for attack_type, patterns in LogParser.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message):
                    detected.append(attack_type)
                    break

        return detected


class AnomalyDetector:
    """Simple anomaly detection using statistical methods."""

    def __init__(self, window_size: int = 100):
        """
        Initialize anomaly detector.

        Args:
            window_size: Size of sliding window for statistics
        """
        self.window_size = window_size
        self.request_counts = []
        self.error_counts = []
        self.status_codes = []

    def update(self, log_entry: Dict[str, Any]) -> None:
        """
        Update detector with new log entry.

        Args:
            log_entry: Log entry
        """
        # Extract status code if available
        status = log_entry.get("status")
        if status:
            self.status_codes.append(status)
            if status >= 400:
                self.error_counts.append(1)
            else:
                self.error_counts.append(0)

        self.request_counts.append(1)

        # Maintain window size
        if len(self.request_counts) > self.window_size:
            self.request_counts.pop(0)
            self.error_counts.pop(0)
            if len(self.status_codes) > self.window_size:
                self.status_codes.pop(0)

    def detect_anomaly(self, threshold: float = 0.7) -> float:
        """
        Detect anomaly score.

        Args:
            threshold: Anomaly threshold

        Returns:
            Anomaly score (0-1)
        """
        if len(self.request_counts) < 10:
            return 0.0

        # Calculate error rate
        error_rate = np.mean(self.error_counts) if self.error_counts else 0.0

        # Calculate request rate (requests per second approximation)
        request_rate = len(self.request_counts) / self.window_size

        # Anomaly if high error rate or very high request rate
        anomaly_score = 0.0
        if error_rate > 0.3:  # More than 30% errors
            anomaly_score = min(1.0, error_rate * 2)
        elif request_rate > 10:  # Very high request rate
            anomaly_score = min(1.0, (request_rate - 10) / 20)

        return anomaly_score


class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log file monitoring."""

    def __init__(self, callback):
        """
        Initialize handler.

        Args:
            callback: Callback function for new log lines
        """
        self.callback = callback
        self.last_position = {}

    def on_modified(self, event):
        """Handle file modification event."""
        if not event.is_directory:
            self.callback(event.src_path)


class LogMonitorAgent:
    """Log Monitor Agent for real-time log analysis."""

    def __init__(
        self,
        log_paths: List[str],
        llm_client: Optional[LLMClient] = None,
        rag_engine: Optional[RAGEngine] = None,
        anomaly_threshold: float = 0.7,
    ):
        """
        Initialize log monitor agent.

        Args:
            log_paths: List of log file paths to monitor
            llm_client: LLM client for analysis
            rag_engine: RAG engine for context
            anomaly_threshold: Threshold for anomaly detection
        """
        self.log_paths = [Path(p) for p in log_paths]
        self.llm_client = llm_client
        self.rag_engine = rag_engine
        self.anomaly_threshold = anomaly_threshold
        self.parser = LogParser()
        self.anomaly_detector = AnomalyDetector()
        self.observer = None
        self.running = False
        self.alerts: List[Dict[str, Any]] = []

    def _parse_log_line(self, line: str, log_type: str = "syslog") -> Optional[Dict[str, Any]]:
        """
        Parse a log line based on log type.

        Args:
            line: Log line
            log_type: Type of log (syslog, apache, nginx)

        Returns:
            Parsed log entry or None
        """
        if log_type == "syslog":
            return self.parser.parse_syslog(line)
        elif log_type == "apache":
            return self.parser.parse_apache(line)
        elif log_type == "nginx":
            return self.parser.parse_nginx(line)
        return None

    def _detect_log_type(self, file_path: Path) -> str:
        """
        Detect log type from file path.

        Args:
            file_path: Path to log file

        Returns:
            Log type
        """
        path_str = str(file_path).lower()
        if "apache" in path_str or "httpd" in path_str:
            return "apache"
        elif "nginx" in path_str:
            return "nginx"
        elif "windows" in path_str or "event" in path_str:
            return "windows"
        return "syslog"

    async def _process_log_line(self, line: str, log_type: str) -> Optional[Dict[str, Any]]:
        """
        Process a single log line.

        Args:
            line: Log line
            log_type: Type of log

        Returns:
            Alert if threat detected, None otherwise
        """
        if not line.strip():
            return None

        # Parse log entry
        log_entry = self._parse_log_line(line, log_type)
        if not log_entry:
            return None

        # Update anomaly detector
        self.anomaly_detector.update(log_entry)

        # Detect attack patterns
        attack_patterns = self.parser.detect_attack_patterns(log_entry)

        # Check for anomalies
        anomaly_score = self.anomaly_detector.detect_anomaly(self.anomaly_threshold)

        # Determine severity
        severity = "low"
        if attack_patterns or anomaly_score > self.anomaly_threshold:
            if anomaly_score > 0.9 or "SQL_INJECTION" in attack_patterns:
                severity = "critical"
            elif anomaly_score > 0.7 or len(attack_patterns) > 1:
                severity = "high"
            else:
                severity = "medium"

        # Create alert if threat detected
        if attack_patterns or anomaly_score > self.anomaly_threshold:
            alert = {
                "id": f"alert_{datetime.utcnow().timestamp()}",
                "type": "log_alert",
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat(),
                "log_entry": log_entry,
                "attack_patterns": attack_patterns,
                "anomaly_score": float(anomaly_score),
                "message": f"Threat detected: {', '.join(attack_patterns) if attack_patterns else 'Anomaly detected'}",
            }

            self.alerts.append(alert)
            logger.warning(f"Alert generated: {alert['message']}")
            return alert

        return None

    async def analyze_logs(self, log_file: Path, max_lines: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Analyze existing log file.

        Args:
            log_file: Path to log file
            max_lines: Maximum number of lines to process

        Returns:
            List of alerts
        """
        alerts = []
        log_type = self._detect_log_type(log_file)

        if not log_file.exists():
            logger.warning(f"Log file not found: {log_file}")
            return alerts

        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                if max_lines:
                    lines = lines[-max_lines:]  # Process last N lines

                for line in lines:
                    alert = await self._process_log_line(line.strip(), log_type)
                    if alert:
                        alerts.append(alert)

        except Exception as e:
            logger.error(f"Error reading log file {log_file}: {str(e)}")

        return alerts

    async def start_monitoring(self, callback=None):
        """
        Start real-time log monitoring.

        Args:
            callback: Optional callback function for alerts
        """
        if self.running:
            logger.warning("Log monitoring already running")
            return

        self.running = True

        async def process_file(file_path: str):
            """Process file for new lines."""
            path = Path(file_path)
            if not path.exists():
                return

            log_type = self._detect_log_type(path)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    # Seek to end for new content
                    f.seek(0, 2)
                    while self.running:
                        line = f.readline()
                        if line:
                            alert = await self._process_log_line(line.strip(), log_type)
                            if alert and callback:
                                await callback(alert)
                        else:
                            await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Error monitoring {file_path}: {str(e)}")

        # Start file watcher
        self.observer = Observer()

        def on_modified(event):
            if not event.is_directory:
                asyncio.create_task(process_file(event.src_path))

        handler = LogFileHandler(on_modified)

        for log_path in self.log_paths:
            if log_path.exists() or log_path.is_dir():
                parent_dir = log_path.parent if log_path.is_file() else log_path
                self.observer.schedule(handler, str(parent_dir), recursive=False)

        self.observer.start()
        logger.info("Log monitoring started")

    def stop_monitoring(self):
        """Stop log monitoring."""
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
        logger.info("Log monitoring stopped")

    def get_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get alerts, optionally filtered by severity.

        Args:
            severity: Optional severity filter

        Returns:
            List of alerts
        """
        if severity:
            return [a for a in self.alerts if a.get("severity") == severity]
        return self.alerts

    async def get_summary(self) -> Dict[str, Any]:
        """
        Get monitoring summary.

        Returns:
            Summary dictionary
        """
        return {
            "status": "running" if self.running else "stopped",
            "log_paths": [str(p) for p in self.log_paths],
            "total_alerts": len(self.alerts),
            "alerts_by_severity": {
                "critical": len([a for a in self.alerts if a.get("severity") == "critical"]),
                "high": len([a for a in self.alerts if a.get("severity") == "high"]),
                "medium": len([a for a in self.alerts if a.get("severity") == "medium"]),
                "low": len([a for a in self.alerts if a.get("severity") == "low"]),
            },
            "anomaly_score": float(self.anomaly_detector.detect_anomaly()),
        }

