"""
LangGraph Orchestrator for multi-agent coordination.
Manages agent workflow, state, and collaboration.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from core.llm_client import LLMClient
from core.rag_engine import RAGEngine

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    """State structure for LangGraph orchestration."""

    incidents: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    current_task: str
    agent_context: Dict[str, Any]
    rag_context: List[str]
    remediation_steps: List[str]
    vulnerabilities: List[Dict[str, Any]]
    compliance_issues: List[Dict[str, Any]]
    threat_intel: Dict[str, Any]
    metadata: Dict[str, Any]


class Orchestrator:
    """Orchestrator for coordinating multiple security agents."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        rag_engine: Optional[RAGEngine] = None,
    ):
        """
        Initialize orchestrator.

        Args:
            llm_client: LLM client instance
            rag_engine: RAG engine instance
        """
        self.llm_client = llm_client or LLMClient()
        self.rag_engine = rag_engine or RAGEngine()
        self.graph = self._build_graph()
        self.app = self.graph.compile()

    def _build_graph(self) -> StateGraph:
        """
        Build LangGraph StateGraph for agent orchestration.

        Returns:
            Configured StateGraph
        """
        workflow = StateGraph(AgentState)

        # Add router node
        workflow.add_node("router", self._router_node)
        
        # Add nodes for each agent
        workflow.add_node("log_monitor", self._log_monitor_node)
        workflow.add_node("threat_intelligence", self._threat_intelligence_node)
        workflow.add_node("vulnerability_scanner", self._vulnerability_scanner_node)
        workflow.add_node("incident_response", self._incident_response_node)
        workflow.add_node("policy_checker", self._policy_checker_node)

        # Define entry point
        workflow.set_entry_point("router")

        # Add routing logic
        workflow.add_conditional_edges(
            "router",
            self._route_task,
            {
                "log_monitor": "log_monitor",
                "threat_intelligence": "threat_intelligence",
                "vulnerability_scanner": "vulnerability_scanner",
                "incident_response": "incident_response",
                "policy_checker": "policy_checker",
                "end": END,
            },
        )

        # Connect agents to incident response for synthesis
        workflow.add_edge("log_monitor", "incident_response")
        workflow.add_edge("threat_intelligence", "incident_response")
        workflow.add_edge("vulnerability_scanner", "incident_response")
        workflow.add_edge("policy_checker", "incident_response")

        # Final edge
        workflow.add_edge("incident_response", END)

        return workflow

    async def _router_node(self, state: AgentState) -> AgentState:
        """
        Router node that determines which agents to invoke.

        Args:
            state: Current state

        Returns:
            Updated state
        """
        # Router just passes through, routing logic is in _route_task
        return state

    def _route_task(self, state: AgentState) -> str:
        """
        Route task to appropriate agent(s).

        Args:
            state: Current agent state

        Returns:
            Next node name
        """
        task = state.get("current_task", "").lower()

        if "log" in task or "monitor" in task:
            return "log_monitor"
        elif "threat" in task or "ioc" in task or "cve" in task:
            return "threat_intelligence"
        elif "vulnerability" in task or "scan" in task or "sast" in task:
            return "vulnerability_scanner"
        elif "policy" in task or "compliance" in task:
            return "policy_checker"
        elif "incident" in task or "remediation" in task:
            return "incident_response"
        else:
            # Default: run all agents
            return "log_monitor"

    async def _log_monitor_node(self, state: AgentState) -> AgentState:
        """
        Log monitor agent node.

        Args:
            state: Current state

        Returns:
            Updated state
        """
        logger.info("Executing log monitor agent")
        # This will be implemented by the actual log_monitor agent
        # For now, return state with placeholder
        state["alerts"].append(
            {
                "type": "log_alert",
                "severity": "medium",
                "message": "Log monitor agent executed",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        return state

    async def _threat_intelligence_node(self, state: AgentState) -> AgentState:
        """
        Threat intelligence agent node.

        Args:
            state: Current state

        Returns:
            Updated state
        """
        logger.info("Executing threat intelligence agent")
        # This will be implemented by the actual threat_intelligence agent
        state["threat_intel"] = {
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
        }
        return state

    async def _vulnerability_scanner_node(self, state: AgentState) -> AgentState:
        """
        Vulnerability scanner agent node.

        Args:
            state: Current state

        Returns:
            Updated state
        """
        logger.info("Executing vulnerability scanner agent")
        # This will be implemented by the actual vulnerability_scanner agent
        state["vulnerabilities"].append(
            {
                "type": "scan_result",
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        return state

    async def _incident_response_node(self, state: AgentState) -> AgentState:
        """
        Incident response agent node.

        Args:
            state: Current state

        Returns:
            Updated state
        """
        logger.info("Executing incident response agent")

        # Gather context from RAG
        context_query = f"Incident: {state.get('current_task', '')}"
        rag_context = self.rag_engine.get_context(query=context_query)

        # Generate remediation plan using LLM
        prompt = f"""
        Based on the following security incident context, generate a step-by-step remediation plan.

        Incident Details:
        {state.get('current_task', 'N/A')}

        Alerts:
        {state.get('alerts', [])}

        Vulnerabilities:
        {state.get('vulnerabilities', [])}

        Threat Intelligence:
        {state.get('threat_intel', {})}

        Security Knowledge Context:
        {rag_context}

        Provide a detailed remediation plan with actionable steps.
        """

        try:
            remediation_plan = await self.llm_client.generate(
                prompt=prompt,
                system_prompt="You are a cybersecurity incident response expert. Provide clear, actionable remediation steps.",
            )

            # Parse remediation steps
            steps = [
                line.strip()
                for line in remediation_plan.split("\n")
                if line.strip() and (line.strip().startswith(("1.", "2.", "3.", "4.", "5.", "-", "*")))
            ]

            state["remediation_steps"] = steps
            state["incidents"].append(
                {
                    "id": f"inc_{datetime.utcnow().timestamp()}",
                    "status": "analyzed",
                    "remediation_plan": remediation_plan,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        except Exception as e:
            logger.error(f"Failed to generate remediation plan: {str(e)}")
            state["remediation_steps"] = ["Error generating remediation plan"]

        return state

    async def _policy_checker_node(self, state: AgentState) -> AgentState:
        """
        Policy checker agent node.

        Args:
            state: Current state

        Returns:
            Updated state
        """
        logger.info("Executing policy checker agent")
        # This will be implemented by the actual policy_checker agent
        state["compliance_issues"].append(
            {
                "type": "compliance_check",
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
        return state

    async def execute(
        self,
        task: str,
        initial_state: Optional[Dict[str, Any]] = None,
    ) -> AgentState:
        """
        Execute orchestration workflow.

        Args:
            task: Task description
            initial_state: Optional initial state

        Returns:
            Final agent state
        """
        # Initialize state
        state: AgentState = {
            "incidents": [],
            "alerts": [],
            "current_task": task,
            "agent_context": {},
            "rag_context": [],
            "remediation_steps": [],
            "vulnerabilities": [],
            "compliance_issues": [],
            "threat_intel": {},
            "metadata": {
                "started_at": datetime.utcnow().isoformat(),
            },
        }

        if initial_state:
            state.update(initial_state)

        try:
            # Execute graph
            final_state = await self.app.ainvoke(state)
            final_state["metadata"]["completed_at"] = datetime.utcnow().isoformat()
            return final_state

        except Exception as e:
            logger.error(f"Orchestration failed: {str(e)}")
            state["metadata"]["error"] = str(e)
            state["metadata"]["completed_at"] = datetime.utcnow().isoformat()
            return state

    def get_graph_visualization(self) -> str:
        """
        Get graph visualization (for debugging).

        Returns:
            Graph visualization string
        """
        try:
            return self.graph.get_graph().draw_mermaid()
        except Exception:
            return "Graph visualization not available"

