"""
Database models and session management for SQLite.
"""

import os
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class Incident(Base):
    """Incident model."""

    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, default="medium")
    status = Column(String, default="open")
    incident_data = Column(JSON)
    remediation_plan = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Alert(Base):
    """Alert model."""

    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    type = Column(String, nullable=False)
    severity = Column(String, default="medium")
    message = Column(Text, nullable=False)
    source = Column(String)
    alert_data = Column(JSON)
    acknowledged = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Vulnerability(Base):
    """Vulnerability model."""

    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True)
    scanner = Column(String, nullable=False)
    vulnerability_id = Column(String)
    package = Column(String)
    severity = Column(String)
    title = Column(Text)
    description = Column(Text)
    cvss_score = Column(Float)
    vulnerability_data = Column(JSON)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ComplianceReport(Base):
    """Compliance report model."""

    __tablename__ = "compliance_reports"

    id = Column(String, primary_key=True)
    framework = Column(String, nullable=False)
    compliance_score = Column(Float)
    report_data = Column(JSON)
    gaps = Column(JSON)
    recommendations = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class AgentRun(Base):
    """Agent execution run model."""

    __tablename__ = "agent_runs"

    id = Column(String, primary_key=True)
    agent_name = Column(String, nullable=False)
    task = Column(Text)
    status = Column(String, default="running")
    result_data = Column(JSON)
    error = Column(Text)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)


class AuditLog(Base):
    """Audit log model."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user = Column(String)
    action = Column(String, nullable=False)
    resource = Column(String)
    details = Column(JSON)
    ip_address = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/cyber_security.db")

# Create directory if it doesn't exist
os.makedirs(os.path.dirname(DATABASE_URL.replace("sqlite:///", "")), exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

