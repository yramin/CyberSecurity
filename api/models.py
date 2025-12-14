"""
Pydantic models for API requests and responses.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# Request Models
class AgentTriggerRequest(BaseModel):
    """Request to trigger an agent."""

    agent_name: str = Field(..., description="Name of agent to trigger")
    task: str = Field(..., description="Task description")
    parameters: Optional[Dict[str, Any]] = Field(default={}, description="Agent parameters")


class IncidentCreateRequest(BaseModel):
    """Request to create an incident."""

    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Incident description")
    severity: str = Field(default="medium", description="Incident severity")
    incident_data: Optional[Dict[str, Any]] = Field(default={}, description="Incident data")


class AlertAcknowledgeRequest(BaseModel):
    """Request to acknowledge an alert."""

    acknowledged: bool = Field(default=True, description="Acknowledgment status")


# Response Models
class IncidentResponse(BaseModel):
    """Incident response model."""

    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    incident_data: Optional[Dict[str, Any]]
    remediation_plan: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertResponse(BaseModel):
    """Alert response model."""

    id: str
    type: str
    severity: str
    message: str
    source: Optional[str]
    alert_data: Optional[Dict[str, Any]]
    acknowledged: bool
    resolved: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VulnerabilityResponse(BaseModel):
    """Vulnerability response model."""

    id: str
    scanner: str
    vulnerability_id: Optional[str]
    package: Optional[str]
    severity: Optional[str]
    title: Optional[str]
    description: Optional[str]
    cvss_score: Optional[float]
    vulnerability_data: Optional[Dict[str, Any]]
    resolved: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ComplianceReportResponse(BaseModel):
    """Compliance report response model."""

    id: str
    framework: str
    compliance_score: Optional[float]
    report_data: Optional[Dict[str, Any]]
    gaps: Optional[List[Dict[str, Any]]]
    recommendations: Optional[List[Dict[str, Any]]]
    created_at: datetime

    model_config = {"from_attributes": True}


class AgentRunResponse(BaseModel):
    """Agent run response model."""

    id: str
    agent_name: str
    task: Optional[str]
    status: str
    result_data: Optional[Dict[str, Any]]
    error: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    timestamp: datetime


class WebSocketMessage(BaseModel):
    """WebSocket message model."""

    type: str = Field(..., description="Message type")
    data: Dict[str, Any] = Field(..., description="Message data")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

