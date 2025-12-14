"""
Streamlit app for Cyber Security AI Agent System
Deployable on Streamlit Cloud
"""

import streamlit as st
import os
import tempfile
import asyncio
from pathlib import Path
from datetime import datetime
import json

# Set page config
st.set_page_config(
    page_title="Cyber Security AI Agent System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'incidents' not in st.session_state:
    st.session_state.incidents = []
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = []

# Import agents (lazy loading)
@st.cache_resource
def initialize_agents():
    """Initialize agents with lazy loading."""
    try:
        from core.llm_client import LLMClient
        from core.rag_engine import RAGEngine
        from agents.vulnerability_scanner import VulnerabilityScannerAgent
        from agents.incident_response import IncidentResponseAgent
        from agents.threat_intelligence import ThreatIntelligenceAgent
        from agents.log_monitor import LogMonitorAgent
        
        # Initialize core services
        llm_client = None
        try:
            llm_client = LLMClient()
        except Exception as e:
            st.warning(f"LLM client not available: {e}")
        
        rag_engine = RAGEngine()
        
        # Initialize agents
        vuln_scanner = VulnerabilityScannerAgent(
            llm_client=llm_client,
            rag_engine=rag_engine,
        )
        
        incident_response = IncidentResponseAgent(
            llm_client=llm_client,
            rag_engine=rag_engine,
        )
        
        threat_intel = ThreatIntelligenceAgent(
            llm_client=llm_client,
            rag_engine=rag_engine,
        )
        
        return {
            'vuln_scanner': vuln_scanner,
            'incident_response': incident_response,
            'threat_intel': threat_intel,
            'llm_client': llm_client,
            'rag_engine': rag_engine,
        }
    except Exception as e:
        st.error(f"Failed to initialize agents: {e}")
        return None

# Main UI
st.title("🔒 Cyber Security AI Agent System")
st.markdown("Multi-agent RAG system for cybersecurity analysis and incident response")

# Sidebar
with st.sidebar:
    st.header("Configuration")
    
    # API Keys
    anthropic_key = st.text_input(
        "Anthropic API Key",
        type="password",
        value=os.getenv("ANTHROPIC_API_KEY", st.secrets.get("ANTHROPIC_API_KEY", "") if hasattr(st, 'secrets') else ""),
        help="Required for LLM features"
    )
    if anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = anthropic_key
    
    virustotal_key = st.text_input(
        "VirusTotal API Key",
        type="password",
        value=os.getenv("VIRUSTOTAL_API_KEY", st.secrets.get("VIRUSTOTAL_API_KEY", "") if hasattr(st, 'secrets') else ""),
        help="Optional: For threat intelligence"
    )
    if virustotal_key:
        os.environ["VIRUSTOTAL_API_KEY"] = virustotal_key
    
    st.divider()
    
    # Agent status
    agents = initialize_agents()
    if agents:
        st.success("✅ Agents initialized")
        if agents['llm_client']:
            st.success("✅ LLM client available")
        else:
            st.warning("⚠️ LLM client not available")
    else:
        st.error("❌ Agents not available")

# Main tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📤 File Upload & Scan",
    "🔍 Vulnerability Scanner",
    "🚨 Incident Response",
    "📊 Threat Intelligence",
    "📋 Alerts & Incidents"
])

# Tab 1: File Upload & Scan
with tab1:
    st.header("Upload Files for Security Analysis")
    
    uploaded_files = st.file_uploader(
        "Choose files to scan",
        type=['txt', 'log', 'py', 'js', 'json', 'yaml', 'yml', 'xml', 'html', 'conf', 'config'],
        accept_multiple_files=True,
        help="Upload log files, code files, or configuration files for security analysis"
    )
    
    if uploaded_files and agents:
        if st.button("🔍 Start Security Scan", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            all_results = []
            
            for idx, uploaded_file in enumerate(uploaded_files):
                status_text.text(f"Scanning {uploaded_file.name}...")
                progress_bar.progress((idx + 1) / len(uploaded_files))
                
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    tmp_path = tmp_file.name
                
                try:
                    # Determine scan type based on file extension
                    file_ext = Path(uploaded_file.name).suffix.lower()
                    
                    if file_ext in ['.log', '.txt']:
                        # Log file analysis
                        from agents.log_monitor import LogMonitorAgent
                        log_monitor = LogMonitorAgent(
                            log_paths=[tmp_path],
                            llm_client=agents['llm_client'],
                            rag_engine=agents['rag_engine'],
                        )
                        alerts = asyncio.run(log_monitor.analyze_logs(Path(tmp_path)))
                        all_results.append({
                            'file': uploaded_file.name,
                            'type': 'log_analysis',
                            'alerts': alerts,
                        })
                        if alerts:
                            st.session_state.alerts.extend(alerts)
                    
                    elif file_ext in ['.py']:
                        # Python code scanning
                        scan_result = asyncio.run(
                            agents['vuln_scanner'].scan_code_directory(
                                str(Path(tmp_path).parent)
                            )
                        )
                        all_results.append({
                            'file': uploaded_file.name,
                            'type': 'code_scan',
                            'result': scan_result,
                        })
                        st.session_state.scan_results.append(scan_result)
                    
                    else:
                        # Generic file analysis - check for IOCs in content
                        try:
                            with open(tmp_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Check for suspicious patterns
                            suspicious_patterns = []
                            if 'password' in content.lower() and '=' in content:
                                suspicious_patterns.append('Potential password exposure')
                            if 'api_key' in content.lower() or 'apikey' in content.lower():
                                suspicious_patterns.append('Potential API key exposure')
                            if 'secret' in content.lower() and '=' in content:
                                suspicious_patterns.append('Potential secret exposure')
                            
                            # Check for IOCs (first 1000 chars)
                            ioc_result = None
                            if len(content) > 0:
                                # Extract potential IOCs
                                import re
                                # Look for IPs, URLs, hashes
                                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                                url_pattern = r'https?://[^\s]+'
                                hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
                                
                                potential_iocs = []
                                potential_iocs.extend(re.findall(ip_pattern, content[:1000]))
                                potential_iocs.extend(re.findall(url_pattern, content[:1000]))
                                potential_iocs.extend(re.findall(hash_pattern, content[:1000]))
                                
                                if potential_iocs and agents['threat_intel']:
                                    # Check first IOC
                                    first_ioc = potential_iocs[0]
                                    try:
                                        ioc_result = asyncio.run(
                                            agents['threat_intel'].check_ioc(first_ioc, "auto")
                                        )
                                    except:
                                        pass
                            
                            all_results.append({
                                'file': uploaded_file.name,
                                'type': 'generic_analysis',
                                'suspicious_patterns': suspicious_patterns,
                                'ioc_check': ioc_result,
                            })
                        except Exception as e:
                            all_results.append({
                                'file': uploaded_file.name,
                                'type': 'generic_analysis',
                                'error': str(e),
                            })
                    
                    # Clean up temp file
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    
                except Exception as e:
                    st.error(f"Error scanning {uploaded_file.name}: {e}")
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            
            status_text.text("✅ Scan complete!")
            progress_bar.progress(1.0)
            
            # Display results
            st.subheader("📊 Scan Results")
            for result in all_results:
                with st.expander(f"📄 {result['file']} - {result['type']}", expanded=True):
                    if 'alerts' in result and result['alerts']:
                        st.warning(f"⚠️ {len(result['alerts'])} alert(s) found")
                        for alert in result['alerts']:
                            st.json(alert)
                    elif 'result' in result:
                        st.json(result['result'])
                    elif 'suspicious_patterns' in result:
                        if result['suspicious_patterns']:
                            st.warning("⚠️ Suspicious patterns detected:")
                            for pattern in result['suspicious_patterns']:
                                st.write(f"- {pattern}")
                        if result.get('ioc_check'):
                            st.info("🔍 IOC Check Result:")
                            st.json(result['ioc_check'])
                    else:
                        st.json(result)
            
            # Auto-trigger incident response if threats found
            threats_found = False
            threat_alerts = []
            
            for result in all_results:
                if 'alerts' in result and result['alerts']:
                    threats_found = True
                    threat_alerts.extend(result['alerts'])
                elif 'suspicious_patterns' in result and result['suspicious_patterns']:
                    threats_found = True
            
            if threats_found:
                st.warning("⚠️ Threats detected! Generating incident response...")
                with st.spinner("Analyzing incident..."):
                    incident_data = {
                        'id': f"inc_{datetime.utcnow().timestamp()}",
                        'type': 'file_scan_threat',
                        'description': f"Threats detected in uploaded files",
                        'severity': 'high' if threat_alerts else 'medium',
                        'files': [r['file'] for r in all_results],
                        'alerts': threat_alerts,
                    }
                    
                    if agents['incident_response'] and agents['llm_client']:
                        try:
                            analysis = asyncio.run(
                                agents['incident_response'].analyze_incident(incident_data)
                            )
                            st.session_state.incidents.append(analysis)
                            
                            st.success("✅ Incident response plan generated!")
                            st.subheader("📋 Remediation Plan")
                            
                            remediation = analysis.get('remediation_plan', {})
                            if isinstance(remediation, dict):
                                plan_text = remediation.get('plan_text', 'No plan generated')
                                steps = remediation.get('steps', [])
                                
                                if plan_text:
                                    st.markdown(plan_text)
                                
                                if steps:
                                    st.subheader("Step-by-Step Actions")
                                    for step in steps:
                                        st.markdown(f"**Step {step.get('step_number', '?')}: {step.get('title', 'N/A')}**")
                                        if step.get('description'):
                                            st.write(step['description'])
                                        if step.get('commands'):
                                            st.code('\n'.join(step['commands']))
                            else:
                                st.markdown(str(remediation))
                        except Exception as e:
                            st.error(f"Failed to generate incident response: {e}")
                    else:
                        st.warning("⚠️ Incident response agent not available (LLM required)")

# Tab 2: Vulnerability Scanner
with tab2:
    st.header("Vulnerability Scanner")
    
    if st.session_state.scan_results:
        st.subheader("Recent Scan Results")
        for idx, result in enumerate(st.session_state.scan_results):
            with st.expander(f"Scan Result #{idx + 1}", expanded=True):
                if isinstance(result, dict):
                    if 'vulnerabilities' in result:
                        st.metric("Vulnerabilities Found", len(result['vulnerabilities']))
                        for vuln in result.get('vulnerabilities', [])[:10]:
                            severity = vuln.get('severity', 'unknown')
                            severity_color = {
                                'critical': '🔴',
                                'high': '🟠',
                                'medium': '🟡',
                                'low': '🟢'
                            }.get(severity.lower(), '⚪')
                            st.write(f"{severity_color} **{vuln.get('id', 'N/A')}** - {vuln.get('title', 'N/A')}")
                    else:
                        st.json(result)
                else:
                    st.json(result)
    else:
        st.info("No scan results yet. Upload files in the 'File Upload & Scan' tab.")

# Tab 3: Incident Response
with tab3:
    st.header("Incident Response")
    
    # Manual incident creation
    with st.form("create_incident"):
        st.subheader("Create New Incident")
        incident_title = st.text_input("Incident Title", placeholder="e.g., SQL Injection Attempt Detected")
        incident_description = st.text_area("Description", placeholder="Describe the security incident...")
        incident_severity = st.selectbox("Severity", ["low", "medium", "high", "critical"])
        
        submitted = st.form_submit_button("🚨 Create Incident & Generate Response Plan", type="primary")
        
        if submitted and incident_title and agents:
            if not agents['llm_client']:
                st.error("❌ LLM client not available. Please add ANTHROPIC_API_KEY in sidebar.")
            else:
                with st.spinner("Analyzing incident and generating response plan..."):
                    incident_data = {
                        'id': f"inc_{datetime.utcnow().timestamp()}",
                        'type': incident_title,
                        'description': incident_description,
                        'severity': incident_severity,
                    }
                    
                    if agents['incident_response']:
                        try:
                            analysis = asyncio.run(
                                agents['incident_response'].analyze_incident(incident_data)
                            )
                            st.session_state.incidents.append(analysis)
                            
                            st.success("✅ Incident analyzed!")
                            st.subheader("📋 Remediation Plan")
                            
                            remediation = analysis.get('remediation_plan', {})
                            if isinstance(remediation, dict):
                                plan_text = remediation.get('plan_text', 'No plan generated')
                                steps = remediation.get('steps', [])
                                
                                if plan_text:
                                    st.markdown(plan_text)
                                
                                if steps:
                                    st.subheader("Step-by-Step Actions")
                                    for step in steps:
                                        st.markdown(f"**Step {step.get('step_number', '?')}: {step.get('title', 'N/A')}**")
                                        if step.get('description'):
                                            st.write(step['description'])
                                        if step.get('commands'):
                                            st.code('\n'.join(step['commands']))
                            else:
                                st.markdown(str(remediation))
                        except Exception as e:
                            st.error(f"Failed to analyze incident: {e}")
    
    # Display existing incidents
    if st.session_state.incidents:
        st.divider()
        st.subheader("Recent Incidents")
        for idx, incident in enumerate(reversed(st.session_state.incidents[-5:])):
            with st.expander(f"Incident #{len(st.session_state.incidents) - idx}", expanded=False):
                if isinstance(incident, dict):
                    st.write(f"**ID:** {incident.get('incident_id', 'N/A')}")
                    st.write(f"**Severity:** {incident.get('severity', 'N/A')}")
                    st.write(f"**Status:** {incident.get('status', 'N/A')}")
                    if incident.get('remediation_plan'):
                        st.markdown("**Remediation Plan:**")
                        st.json(incident['remediation_plan'])
                else:
                    st.json(incident)

# Tab 4: Threat Intelligence
with tab4:
    st.header("Threat Intelligence")
    
    ioc_input = st.text_input("Enter IOC (IP, URL, Hash, or Domain)", placeholder="e.g., 192.168.1.1 or example.com")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        check_button = st.button("🔍 Check IOC", type="primary")
    
    if check_button and ioc_input and agents:
        if agents['threat_intel']:
            with st.spinner("Checking IOC..."):
                try:
                    result = asyncio.run(agents['threat_intel'].check_ioc(ioc_input))
                    
                    if result:
                        st.subheader("IOC Analysis Results")
                        
                        if 'risk_score' in result:
                            risk_score = result['risk_score']
                            if risk_score > 0.7:
                                st.error(f"🔴 High Risk Score: {risk_score:.2f}")
                            elif risk_score > 0.4:
                                st.warning(f"🟠 Medium Risk Score: {risk_score:.2f}")
                            else:
                                st.success(f"🟢 Low Risk Score: {risk_score:.2f}")
                        
                        if 'sources' in result:
                            st.subheader("Threat Intelligence Sources")
                            for source, data in result['sources'].items():
                                with st.expander(f"Source: {source}"):
                                    st.json(data)
                        
                        st.json(result)
                except Exception as e:
                    st.error(f"Failed to check IOC: {e}")
        else:
            st.warning("Threat intelligence agent not available")

# Tab 5: Alerts & Incidents
with tab5:
    st.header("Alerts & Incidents Summary")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Alerts", len(st.session_state.alerts))
        critical_alerts = len([a for a in st.session_state.alerts if a.get('severity') == 'critical'])
        st.metric("Critical Alerts", critical_alerts, delta=None)
    
    with col2:
        st.metric("Total Incidents", len(st.session_state.incidents))
        high_incidents = len([i for i in st.session_state.incidents if isinstance(i, dict) and i.get('severity') == 'high'])
        st.metric("High Severity", high_incidents, delta=None)
    
    with col3:
        st.metric("Scan Results", len(st.session_state.scan_results))
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Recent Alerts")
        if st.session_state.alerts:
            for alert in reversed(st.session_state.alerts[-10:]):
                severity = alert.get('severity', 'unknown')
                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(severity, '⚪')
                
                with st.expander(f"{severity_icon} {alert.get('message', 'Alert')}", expanded=False):
                    st.json(alert)
        else:
            st.info("No alerts yet")
    
    with col2:
        st.subheader("Recent Incidents")
        if st.session_state.incidents:
            for idx, incident in enumerate(reversed(st.session_state.incidents[-5:])):
                if isinstance(incident, dict):
                    incident_id = incident.get('incident_id', f'Incident #{len(st.session_state.incidents) - idx}')
                    severity = incident.get('severity', 'unknown')
                    with st.expander(f"🚨 {incident_id} ({severity})", expanded=False):
                        st.json(incident)
                else:
                    st.json(incident)
        else:
            st.info("No incidents yet")

# Footer
st.divider()
st.markdown("---")
st.markdown("**Cyber Security AI Agent System** | Powered by LangGraph, Claude, and ChromaDB")
st.markdown("Upload files for security analysis, check IOCs, and generate automated incident response plans")

