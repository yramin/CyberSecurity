# Cyber Security AI Agent System

A comprehensive multi-agent RAG-based cybersecurity system with real-time log monitoring, threat intelligence, vulnerability scanning, incident response, and policy compliance checking.

## Architecture Overview

The system uses a multi-agent architecture orchestrated by LangGraph, where specialized agents collaborate through a shared RAG knowledge base and state management. Real-time updates flow from agents → FastAPI → WebSocket → React dashboard.

### Key Components

- **Multi-Agent System**: Five specialized agents (Log Monitor, Threat Intelligence, Vulnerability Scanner, Incident Response, Policy Checker)
- **RAG Engine**: ChromaDB-based vector store with security knowledge base (MITRE ATT&CK, CWE, OWASP)
- **LLM Integration**: Claude Sonnet 4 via Anthropic API for intelligent analysis
- **Real-time Monitoring**: WebSocket-based real-time updates to dashboard
- **RESTful API**: FastAPI backend with comprehensive endpoints
- **Modern Frontend**: React dashboard with Material-UI

## Features

### 1. Log Monitor Agent
- Real-time log parsing (syslog, Apache, nginx, Windows Event logs)
- Pattern matching for attack signatures
- ML-based anomaly detection
- Alert generation with severity scoring

### 2. Threat Intelligence Agent
- VirusTotal API integration for IOC checking
- CVE database queries (NVD API)
- MITRE ATT&CK technique mapping
- Threat feed aggregation

### 3. Vulnerability Scanner Agent
- Trivy integration for Docker image scanning
- Bandit for Python SAST
- Safety for dependency vulnerability checks
- OWASP ZAP for API security testing

### 4. Incident Response Agent
- Automated incident analysis using RAG + LLM
- Step-by-step remediation plan generation
- SOAR-style playbook creation
- Integration with other agents for context

### 5. Policy Checker Agent
- Compliance checking (ISO 27001, NIST, SOC2)
- Configuration auditing
- Compliance gap analysis
- Fix recommendations with code examples

## Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend)
- Docker and Docker Compose (optional)
- API Keys:
  - Anthropic API key (required)
  - VirusTotal API key (optional but recommended)
  - NVD API key (optional but recommended for higher rate limits)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cyber-security-agent
```

### 2. Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env and add your API keys

# Initialize database
python -c "from api.database import init_db; init_db()"

# Ingest knowledge base
python scripts/ingest_knowledge_base.py
```

### 3. Frontend Setup

```bash
cd frontend/dashboard

# Install dependencies
npm install

# Start development server
npm run dev
```

### 4. Run Backend

```bash
# From project root
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

## Docker Deployment

### Using Docker Compose

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Individual Docker Builds

```bash
# Build backend
docker build -t cyber-security-backend .

# Build frontend
cd frontend/dashboard
docker build -t cyber-security-frontend .
```

## Configuration

### Environment Variables

Key environment variables (see `.env.example`):

- `ANTHROPIC_API_KEY`: Anthropic API key (required)
- `VIRUSTOTAL_API_KEY`: VirusTotal API key (optional)
- `NVD_API_KEY`: NVD API key (optional)
- `DATABASE_URL`: Database connection string
- `BASIC_AUTH_USERNAME`: Basic auth username (default: admin)
- `BASIC_AUTH_PASSWORD`: Basic auth password (default: admin123)

### Agent Configuration

Edit `config/agents_config.yaml` to customize agent behavior, thresholds, and settings.

## Usage

### API Endpoints

#### Health Check
```bash
GET /api/v1/health
```

#### Trigger Agent
```bash
POST /api/v1/agents/trigger
{
  "agent_name": "log_monitor",
  "task": "Analyze logs for security threats",
  "parameters": {}
}
```

#### Get Incidents
```bash
GET /api/v1/incidents?skip=0&limit=100&severity=high
```

#### Create Incident
```bash
POST /api/v1/incidents
{
  "title": "Security Breach Detected",
  "description": "Unauthorized access attempt detected",
  "severity": "critical"
}
```

#### Get Alerts
```bash
GET /api/v1/alerts?skip=0&limit=100&severity=critical
```

#### Acknowledge Alert
```bash
POST /api/v1/alerts/{alert_id}/acknowledge
{
  "acknowledged": true
}
```

#### Get Vulnerabilities
```bash
GET /api/v1/vulnerabilities?skip=0&limit=100&severity=high
```

#### Get Compliance Reports
```bash
GET /api/v1/compliance?framework=ISO27001
```

### WebSocket Connection

Connect to `ws://localhost:8000/ws` for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

### Frontend Dashboard

Access the dashboard at `http://localhost:3000` (development) or `http://localhost` (Docker).

Features:
- Real-time dashboard with metrics and charts
- Alert feed with acknowledgment
- Incident management
- Compliance reports
- WebSocket-based real-time updates

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_llm_client.py
```

## Project Structure

```
cyber-security-agent/
├── agents/                 # Agent implementations
│   ├── log_monitor.py
│   ├── threat_intelligence.py
│   ├── vulnerability_scanner.py
│   ├── incident_response.py
│   └── policy_checker.py
├── core/                   # Core services
│   ├── llm_client.py
│   ├── rag_engine.py
│   └── orchestrator.py
├── api/                    # FastAPI application
│   ├── main.py
│   ├── models.py
│   └── database.py
├── frontend/dashboard/     # React frontend
│   ├── src/
│   │   ├── components/
│   │   ├── hooks/
│   │   └── services/
│   └── package.json
├── data/                   # Data files
│   ├── knowledge_base/     # Security knowledge base
│   └── sample_logs/        # Sample log files
├── config/                  # Configuration files
│   └── agents_config.yaml
├── tests/                   # Test files
├── scripts/                 # Utility scripts
│   └── ingest_knowledge_base.py
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Security Considerations

- API key management via environment variables
- Basic authentication for API endpoints (upgrade to JWT in production)
- Input validation on all endpoints
- SQL injection prevention (SQLAlchemy ORM)
- Rate limiting to prevent abuse
- Audit logging for all agent actions and API calls

## Performance Optimizations

- Async/await throughout FastAPI
- Batch processing for log analysis
- Caching for threat intelligence queries
- Connection pooling for database
- Vector search optimization in ChromaDB

## Troubleshooting

### Common Issues

1. **ChromaDB initialization fails**
   - Ensure `data/chroma_db` directory exists and is writable

2. **API key errors**
   - Verify API keys are set in `.env` file
   - Check API key permissions and rate limits

3. **WebSocket connection fails**
   - Verify backend is running on port 8000
   - Check CORS settings in `api/main.py`

4. **Frontend build fails**
   - Ensure Node.js 18+ is installed
   - Run `npm install` to install dependencies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[Specify your license here]

## Support

For issues and questions, please open an issue on GitHub.

## Acknowledgments

- MITRE ATT&CK framework
- OWASP Top 10
- CWE Top 25
- LangGraph for agent orchestration
- ChromaDB for vector storage
- Anthropic Claude for LLM capabilities

