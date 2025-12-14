"""
Incident Response Agent for generating remediation plans and SOAR playbooks.
Uses LLM and RAG to provide actionable incident response guidance.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.llm_client import LLMClient
from core.rag_engine import RAGEngine

logger = logging.getLogger(__name__)


class IncidentResponseAgent:
    """Incident Response Agent for automated remediation planning."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        rag_engine: Optional[RAGEngine] = None,
        playbook_path: Optional[str] = None,
        auto_remediation: bool = False,
        max_remediation_steps: int = 10,
    ):
        """
        Initialize incident response agent.

        Args:
            llm_client: LLM client for analysis
            rag_engine: RAG engine for context
            playbook_path: Path to playbook directory
            auto_remediation: Whether to enable auto-remediation
            max_remediation_steps: Maximum number of remediation steps
        """
        self.llm_client = llm_client or LLMClient()
        self.rag_engine = rag_engine or RAGEngine()
        self.playbook_path = Path(playbook_path) if playbook_path else Path("data/knowledge_base/playbooks/")
        self.auto_remediation = auto_remediation
        self.max_remediation_steps = max_remediation_steps
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self._load_playbooks()

    def _load_playbooks(self):
        """Load SOAR playbooks from directory."""
        if not self.playbook_path.exists():
            self.playbook_path.mkdir(parents=True, exist_ok=True)
            return

        for playbook_file in self.playbook_path.glob("*.json"):
            try:
                with open(playbook_file, "r") as f:
                    playbook = json.load(f)
                    playbook_id = playbook.get("id", playbook_file.stem)
                    self.playbooks[playbook_id] = playbook
            except Exception as e:
                logger.warning(f"Failed to load playbook {playbook_file}: {str(e)}")

    async def analyze_incident(
        self,
        incident_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze security incident and generate response plan.

        Args:
            incident_data: Incident data (alerts, vulnerabilities, etc.)
            context: Additional context from other agents

        Returns:
            Incident analysis and response plan
        """
        logger.info("Analyzing security incident")

        # Gather context from RAG
        incident_type = incident_data.get("type", "unknown")
        rag_context = self.rag_engine.get_context(
            query=f"Security incident response for {incident_type}",
            n_results=5,
        )

        # Build comprehensive prompt
        prompt = self._build_analysis_prompt(incident_data, context, rag_context)

        try:
            # Generate analysis using LLM
            analysis = await self.llm_client.generate(
                prompt=prompt,
                system_prompt=self._get_system_prompt(),
            )

            # Generate remediation plan
            remediation_plan = await self._generate_remediation_plan(
                incident_data, analysis, context
            )

            # Match to playbook if available
            matched_playbook = self._match_playbook(incident_data)

            response = {
                "incident_id": incident_data.get("id", f"inc_{datetime.utcnow().timestamp()}"),
                "timestamp": datetime.utcnow().isoformat(),
                "analysis": analysis,
                "remediation_plan": remediation_plan,
                "matched_playbook": matched_playbook,
                "severity": self._calculate_severity(incident_data),
                "status": "analyzed",
            }

            return response

        except Exception as e:
            logger.error(f"Incident analysis failed: {str(e)}")
            return {
                "incident_id": incident_data.get("id", "unknown"),
                "error": str(e),
                "status": "error",
            }

    def _build_analysis_prompt(
        self,
        incident_data: Dict[str, Any],
        context: Optional[Dict[str, Any]],
        rag_context: str,
    ) -> str:
        """Build analysis prompt for LLM."""
        prompt = f"""
Analyze the following security incident and provide a comprehensive assessment:

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

ADDITIONAL CONTEXT:
{json.dumps(context or {}, indent=2)}

SECURITY KNOWLEDGE BASE:
{rag_context}

Please provide:
1. Incident classification and severity assessment
2. Root cause analysis
3. Impact assessment
4. Recommended immediate actions
5. Long-term remediation recommendations
"""

        return prompt

    def _get_system_prompt(self) -> str:
        """Get system prompt for LLM."""
        return """You are a cybersecurity incident response expert with extensive experience in:
- Threat detection and analysis
- Incident containment and eradication
- Forensic investigation
- Remediation planning
- Security best practices

Provide clear, actionable, and technically accurate guidance. Focus on practical steps that security teams can implement immediately."""

    async def _generate_remediation_plan(
        self,
        incident_data: Dict[str, Any],
        analysis: str,
        context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate step-by-step remediation plan."""
        prompt = f"""
Based on the following incident analysis, generate a detailed, step-by-step remediation plan.

INCIDENT ANALYSIS:
{analysis}

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

CONTEXT:
{json.dumps(context or {}, indent=2)}

Provide a remediation plan with:
1. Immediate containment steps (what to do first)
2. Investigation steps (how to gather more information)
3. Eradication steps (how to remove the threat)
4. Recovery steps (how to restore normal operations)
5. Post-incident steps (lessons learned and prevention)

Format each step with:
- Step number
- Action description
- Expected outcome
- Commands or code examples if applicable
- Estimated time to complete

Limit to {self.max_remediation_steps} steps total.
"""

        try:
            plan_text = await self.llm_client.generate(
                prompt=prompt,
                system_prompt="You are a cybersecurity remediation expert. Provide clear, actionable remediation steps with code examples when applicable.",
            )

            # Parse steps from plan
            steps = self._parse_remediation_steps(plan_text)

            return {
                "plan_text": plan_text,
                "steps": steps,
                "estimated_time": self._estimate_remediation_time(steps),
                "priority": self._determine_priority(incident_data),
            }

        except Exception as e:
            logger.error(f"Failed to generate remediation plan: {str(e)}")
            return {
                "plan_text": "Error generating remediation plan",
                "steps": [],
                "error": str(e),
            }

    def _parse_remediation_steps(self, plan_text: str) -> List[Dict[str, Any]]:
        """Parse remediation steps from plan text."""
        steps = []
        lines = plan_text.split("\n")

        current_step = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect step headers (numbered or bulleted)
            if line[0].isdigit() or line.startswith(("-", "*")):
                if current_step:
                    steps.append(current_step)

                step_num = len(steps) + 1
                current_step = {
                    "step_number": step_num,
                    "title": line.lstrip("0123456789.-* ").strip(),
                    "description": "",
                    "commands": [],
                    "expected_outcome": "",
                }
            elif current_step:
                # Check for code blocks or commands
                if line.startswith("```") or line.startswith("$") or line.startswith(">"):
                    current_step["commands"].append(line)
                elif "outcome" in line.lower() or "expected" in line.lower():
                    current_step["expected_outcome"] = line
                else:
                    current_step["description"] += " " + line

        if current_step:
            steps.append(current_step)

        return steps[:self.max_remediation_steps]

    def _estimate_remediation_time(self, steps: List[Dict[str, Any]]) -> str:
        """Estimate total remediation time."""
        # Rough estimate: 30 minutes per step
        total_minutes = len(steps) * 30
        hours = total_minutes // 60
        minutes = total_minutes % 60

        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"

    def _determine_priority(self, incident_data: Dict[str, Any]) -> str:
        """Determine remediation priority."""
        severity = incident_data.get("severity", "medium").lower()
        severity_map = {
            "critical": "P0 - Immediate",
            "high": "P1 - Urgent",
            "medium": "P2 - High",
            "low": "P3 - Normal",
        }
        return severity_map.get(severity, "P2 - High")

    def _calculate_severity(self, incident_data: Dict[str, Any]) -> str:
        """Calculate incident severity."""
        alerts = incident_data.get("alerts", [])
        vulnerabilities = incident_data.get("vulnerabilities", [])

        # Check for critical alerts
        critical_alerts = [a for a in alerts if a.get("severity") == "critical"]
        if critical_alerts:
            return "critical"

        # Check for high severity
        high_alerts = [a for a in alerts if a.get("severity") == "high"]
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        if high_alerts or critical_vulns:
            return "high"

        # Default to medium
        return "medium"

    def _match_playbook(self, incident_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Match incident to existing playbook."""
        incident_type = incident_data.get("type", "").lower()

        # Simple keyword matching
        for playbook_id, playbook in self.playbooks.items():
            playbook_types = playbook.get("incident_types", [])
            for pt in playbook_types:
                if pt.lower() in incident_type or incident_type in pt.lower():
                    return {
                        "playbook_id": playbook_id,
                        "name": playbook.get("name", ""),
                        "description": playbook.get("description", ""),
                    }

        return None

    async def create_playbook(
        self,
        playbook_data: Dict[str, Any],
        save: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a new SOAR playbook.

        Args:
            playbook_data: Playbook data
            save: Whether to save to disk

        Returns:
            Created playbook
        """
        playbook_id = playbook_data.get("id", f"playbook_{datetime.utcnow().timestamp()}")
        playbook = {
            "id": playbook_id,
            "name": playbook_data.get("name", ""),
            "description": playbook_data.get("description", ""),
            "incident_types": playbook_data.get("incident_types", []),
            "steps": playbook_data.get("steps", []),
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }

        self.playbooks[playbook_id] = playbook

        if save:
            playbook_file = self.playbook_path / f"{playbook_id}.json"
            try:
                with open(playbook_file, "w") as f:
                    json.dump(playbook, f, indent=2)
                logger.info(f"Saved playbook: {playbook_id}")
            except Exception as e:
                logger.error(f"Failed to save playbook: {str(e)}")

        return playbook

    async def execute_remediation_step(
        self,
        step: Dict[str, Any],
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a remediation step (if auto_remediation enabled).

        Args:
            step: Remediation step to execute
            dry_run: Whether to perform dry run

        Returns:
            Execution result
        """
        if not self.auto_remediation:
            return {
                "status": "skipped",
                "reason": "Auto-remediation disabled",
            }

        if dry_run:
            return {
                "status": "dry_run",
                "step": step,
                "message": "Would execute step (dry run mode)",
            }

        # In a real implementation, this would execute the actual commands
        # For safety, we'll just return a placeholder
        return {
            "status": "executed",
            "step": step,
            "message": "Step execution not implemented (safety feature)",
        }

    async def get_summary(self) -> Dict[str, Any]:
        """
        Get agent summary.

        Returns:
            Summary dictionary
        """
        return {
            "status": "active",
            "playbooks_loaded": len(self.playbooks),
            "auto_remediation": self.auto_remediation,
            "max_remediation_steps": self.max_remediation_steps,
        }

