"""
FastAPI application with REST endpoints, WebSocket support, and authentication.
"""

import asyncio
import base64
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from api.database import (
    AgentRun,
    Alert,
    AuditLog,
    ComplianceReport,
    Incident,
    Vulnerability,
    get_db,
    init_db,
)
from api.models import (
    AgentRunResponse,
    AgentTriggerRequest,
    AlertAcknowledgeRequest,
    AlertResponse,
    ComplianceReportResponse,
    HealthResponse,
    IncidentCreateRequest,
    IncidentResponse,
    VulnerabilityResponse,
    WebSocketMessage,
)
from core.llm_client import LLMClient
from core.rag_engine import RAGEngine
from core.orchestrator import Orchestrator

# Initialize agents
from agents.incident_response import IncidentResponseAgent
from agents.log_monitor import LogMonitorAgent
from agents.policy_checker import PolicyCheckerAgent
from agents.threat_intelligence import ThreatIntelligenceAgent
from agents.vulnerability_scanner import VulnerabilityScannerAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cyber Security AI Agent System",
    description="Multi-agent RAG system for cybersecurity",
    version="1.0.0",
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Basic authentication
security = HTTPBasic()

# WebSocket connections
active_connections: List[WebSocket] = []

# Initialize database
init_db()

# Initialize core services (lazy initialization)
llm_client: Optional[LLMClient] = None
rag_engine: Optional[RAGEngine] = None
orchestrator: Optional[Orchestrator] = None

# Initialize agents (lazy initialization)
log_monitor: Optional[LogMonitorAgent] = None
threat_intel: Optional[ThreatIntelligenceAgent] = None
vuln_scanner: Optional[VulnerabilityScannerAgent] = None
incident_response: Optional[IncidentResponseAgent] = None
policy_checker: Optional[PolicyCheckerAgent] = None


def get_llm_client() -> Optional[LLMClient]:
    """Get or create LLM client."""
    global llm_client
    if llm_client is None:
        try:
            llm_client = LLMClient()
        except ValueError as e:
            logger.warning(f"LLM client initialization failed: {e}. Some features may be unavailable.")
            return None
    return llm_client


def get_rag_engine() -> RAGEngine:
    """Get or create RAG engine."""
    global rag_engine
    if rag_engine is None:
        rag_engine = RAGEngine()
    return rag_engine


def initialize_services():
    """Initialize all services."""
    global orchestrator, log_monitor, threat_intel, vuln_scanner, incident_response, policy_checker
    
    try:
        _llm_client = get_llm_client()
        if _llm_client is None:
            logger.warning("LLM client not available. Some features will be limited.")
            return
        
        _rag_engine = get_rag_engine()
        
        if orchestrator is None:
            orchestrator = Orchestrator(llm_client=_llm_client, rag_engine=_rag_engine)
        
        if log_monitor is None:
            log_monitor = LogMonitorAgent(
                log_paths=os.getenv("LOG_PATHS", "data/sample_logs/").split(","),
                llm_client=_llm_client,
                rag_engine=_rag_engine,
            )
        
        if threat_intel is None:
            threat_intel = ThreatIntelligenceAgent(
                llm_client=_llm_client,
                rag_engine=_rag_engine,
            )
        
        if vuln_scanner is None:
            vuln_scanner = VulnerabilityScannerAgent(
                llm_client=_llm_client,
                rag_engine=_rag_engine,
            )
        
        if incident_response is None:
            incident_response = IncidentResponseAgent(
                llm_client=_llm_client,
                rag_engine=_rag_engine,
            )
        
        if policy_checker is None:
            policy_checker = PolicyCheckerAgent(
                llm_client=_llm_client,
                rag_engine=_rag_engine,
            )
    except Exception as e:
        logger.warning(f"Service initialization failed: {e}. Some features may be unavailable.")


# Try to initialize services on startup
try:
    initialize_services()
except Exception as e:
    logger.warning(f"Initial service initialization failed: {e}. Services will be initialized on first use.")


def verify_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify basic authentication."""
    username = os.getenv("BASIC_AUTH_USERNAME", "admin")
    password = os.getenv("BASIC_AUTH_PASSWORD", "admin123")

    if credentials.username != username or credentials.password != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


async def broadcast_message(message: WebSocketMessage):
    """Broadcast message to all WebSocket connections."""
    if active_connections:
        message_dict = message.dict()
        message_dict["timestamp"] = message_dict["timestamp"].isoformat()
        disconnected = []
        for connection in active_connections:
            try:
                await connection.send_json(message_dict)
            except Exception as e:
                logger.warning(f"Failed to send WebSocket message: {str(e)}")
                disconnected.append(connection)
        # Remove disconnected connections
        for conn in disconnected:
            if conn in active_connections:
                active_connections.remove(conn)


def log_audit(user: str, action: str, resource: str, details: Optional[Dict] = None, ip_address: Optional[str] = None):
    """Log audit event."""
    db = next(get_db())
    try:
        audit_log = AuditLog(
            user=user,
            action=action,
            resource=resource,
            details=details or {},
            ip_address=ip_address,
        )
        db.add(audit_log)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log audit event: {str(e)}")
    finally:
        db.close()


# Health check endpoint
@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow(),
    )


# Agent trigger endpoint
@app.post("/api/v1/agents/trigger", response_model=AgentRunResponse)
@limiter.limit("10/minute")
async def trigger_agent(
    http_request: Request,
    request: AgentTriggerRequest,
    username: str = Depends(verify_basic_auth),
    db: Session = Depends(get_db),
):
    """Trigger an agent to execute a task."""
    log_audit(username, "trigger_agent", request.agent_name, {"task": request.task})

    agent_run = AgentRun(
        id=f"run_{datetime.utcnow().timestamp()}",
        agent_name=request.agent_name,
        task=request.task,
        status="running",
    )
    db.add(agent_run)
    db.commit()

    try:
        # Ensure services are initialized
        initialize_services()
        if orchestrator is None:
            raise HTTPException(
                status_code=503,
                detail="Orchestrator service unavailable. Please check configuration."
            )
        
        # Execute agent via orchestrator
        result = await orchestrator.execute(
            task=request.task,
            initial_state={"agent_name": request.agent_name, **request.parameters},
        )

        agent_run.status = "completed"
        agent_run.result_data = result
        agent_run.completed_at = datetime.utcnow()
        db.commit()

        # Broadcast update
        await broadcast_message(
            WebSocketMessage(
                type="agent_completed",
                data={"agent_run_id": agent_run.id, "result": result},
            )
        )

        return AgentRunResponse.model_validate(agent_run)

    except Exception as e:
        logger.error(f"Agent execution failed: {str(e)}")
        agent_run.status = "failed"
        agent_run.error = str(e)
        agent_run.completed_at = datetime.utcnow()
        db.commit()

        raise HTTPException(status_code=500, detail=str(e))


# Incidents endpoints
@app.get("/api/v1/incidents", response_model=List[IncidentResponse])
@limiter.limit("60/minute")
async def get_incidents(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Get list of incidents."""
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    incidents = query.offset(skip).limit(limit).all()
    return [IncidentResponse.model_validate(inc) for inc in incidents]


@app.post("/api/v1/incidents", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_incident(
    http_request: Request,
    request: IncidentCreateRequest,
    username: str = Depends(verify_basic_auth),
    db: Session = Depends(get_db),
):
    """Create a new incident."""
    log_audit(username, "create_incident", "incidents", {"title": request.title})

    incident = Incident(
        id=f"inc_{datetime.utcnow().timestamp()}",
        title=request.title,
        description=request.description,
        severity=request.severity,
        incident_data=request.incident_data,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # Ensure services are initialized
    initialize_services()
    if incident_response is None:
        logger.warning("Incident response agent not available. Skipping analysis.")
        analysis = {"error": "Incident response agent unavailable"}
    else:
        # Analyze incident
        analysis = await incident_response.analyze_incident(
            {
                "id": incident.id,
                "type": request.title,
                "description": request.description,
                "severity": request.severity,
                **request.incident_data,
            }
        )

    incident.remediation_plan = analysis.get("remediation_plan")
    db.commit()

    # Broadcast update
    await broadcast_message(
        WebSocketMessage(
            type="incident_created",
            data={"incident_id": incident.id, "incident": IncidentResponse.model_validate(incident).model_dump()},
        )
    )

    return IncidentResponse.model_validate(incident)


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Get incident by ID."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentResponse.model_validate(incident)


# Alerts endpoints
@app.get("/api/v1/alerts", response_model=List[AlertResponse])
@limiter.limit("60/minute")
async def get_alerts(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """Get list of alerts."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    return [AlertResponse.model_validate(alert) for alert in alerts]


@app.post("/api/v1/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    request: AlertAcknowledgeRequest,
    username: str = Depends(verify_basic_auth),
    db: Session = Depends(get_db),
):
    """Acknowledge an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    log_audit(username, "acknowledge_alert", alert_id)

    alert.acknowledged = request.acknowledged
    db.commit()

    await broadcast_message(
        WebSocketMessage(
            type="alert_acknowledged",
            data={"alert_id": alert_id, "acknowledged": request.acknowledged},
        )
    )

    return AlertResponse.model_validate(alert)


# Vulnerabilities endpoints
@app.get("/api/v1/vulnerabilities", response_model=List[VulnerabilityResponse])
@limiter.limit("60/minute")
async def get_vulnerabilities(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """Get list of vulnerabilities."""
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if resolved is not None:
        query = query.filter(Vulnerability.resolved == resolved)
    vulnerabilities = query.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit).all()
    return [VulnerabilityResponse.model_validate(vuln) for vuln in vulnerabilities]


# Compliance endpoints
@app.get("/api/v1/compliance", response_model=List[ComplianceReportResponse])
@limiter.limit("60/minute")
async def get_compliance_reports(
    request: Request,
    framework: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """Get compliance reports."""
    query = db.query(ComplianceReport)
    if framework:
        query = query.filter(ComplianceReport.framework == framework)
    reports = query.order_by(ComplianceReport.created_at.desc()).offset(skip).limit(limit).all()
    return [ComplianceReportResponse.model_validate(report) for report in reports]


# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            # Keep connection alive and handle incoming messages
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                # Echo back or process message
                await websocket.send_json({"type": "pong", "data": {"message": "received"}})
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await websocket.send_json({"type": "ping", "data": {}})
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

