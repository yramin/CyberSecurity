"""
Policy Checker Agent for compliance checking (ISO 27001, NIST, SOC2).
Performs configuration auditing and generates compliance reports.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.llm_client import LLMClient
from core.rag_engine import RAGEngine

logger = logging.getLogger(__name__)


class ComplianceFramework:
    """Compliance framework definitions."""

    ISO27001_CONTROLS = {
        "A.5.1.1": "Policies for information security",
        "A.5.1.2": "Review of the policies for information security",
        "A.6.1.1": "Information security roles and responsibilities",
        "A.6.1.2": "Segregation of duties",
        "A.7.1.1": "Screening",
        "A.8.1.1": "Inventory of assets",
        "A.9.1.1": "Access control policy",
        "A.9.2.1": "User registration and de-registration",
        "A.10.1.1": "Cryptographic controls",
        "A.12.1.1": "Documented operating procedures",
        "A.12.2.1": "Controls against malicious code",
        "A.12.3.1": "Information backup",
        "A.13.1.1": "Network controls",
        "A.14.1.1": "Information security requirements analysis and specification",
        "A.15.1.1": "Information security policy for supplier relationships",
    }

    NIST_CONTROLS = {
        "AC-1": "Access Control Policy and Procedures",
        "AC-2": "Account Management",
        "AC-3": "Access Enforcement",
        "AC-4": "Information Flow Enforcement",
        "AC-5": "Separation of Duties",
        "AC-6": "Least Privilege",
        "AC-7": "Unsuccessful Logon Attempts",
        "AC-8": "System Use Notification",
        "AC-11": "Session Lock",
        "AC-17": "Remote Access",
        "SI-2": "Flaw Remediation",
        "SI-3": "Malicious Code Protection",
        "SI-4": "Information System Monitoring",
        "SI-7": "Software, Firmware, and Information Integrity",
    }

    SOC2_CONTROLS = {
        "CC1.1": "Control Environment",
        "CC1.2": "Communication and Information",
        "CC2.1": "Communication with External Parties",
        "CC3.1": "Logical and Physical Access Controls",
        "CC4.1": "System Operations",
        "CC5.1": "Logical Access Security Software",
        "CC6.1": "System Boundaries",
        "CC7.1": "System Processing Integrity",
        "CC7.2": "System Backup and Recovery",
        "CC7.3": "System Availability",
    }

    @staticmethod
    def get_controls(framework: str) -> Dict[str, str]:
        """
        Get controls for a framework.

        Args:
            framework: Framework name (ISO27001, NIST, SOC2)

        Returns:
            Dictionary of control IDs and descriptions
        """
        framework_map = {
            "ISO27001": ComplianceFramework.ISO27001_CONTROLS,
            "NIST": ComplianceFramework.NIST_CONTROLS,
            "SOC2": ComplianceFramework.SOC2_CONTROLS,
        }
        return framework_map.get(framework.upper(), {})


class PolicyCheckerAgent:
    """Policy Checker Agent for compliance auditing."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        rag_engine: Optional[RAGEngine] = None,
        frameworks: Optional[List[str]] = None,
    ):
        """
        Initialize policy checker agent.

        Args:
            llm_client: LLM client for analysis
            rag_engine: RAG engine for context
            frameworks: List of frameworks to check (ISO27001, NIST, SOC2)
        """
        self.llm_client = llm_client or LLMClient()
        self.rag_engine = rag_engine or RAGEngine()
        self.frameworks = frameworks or ["ISO27001", "NIST", "SOC2"]
        self.compliance_results: Dict[str, Dict[str, Any]] = {}

    async def check_compliance(
        self,
        configuration: Dict[str, Any],
        framework: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check compliance against framework(s).

        Args:
            configuration: System configuration to check
            framework: Specific framework to check (optional)

        Returns:
            Compliance check results
        """
        frameworks_to_check = [framework] if framework else self.frameworks

        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "configuration": configuration,
            "frameworks": {},
            "overall_compliance": 0.0,
            "gaps": [],
            "recommendations": [],
        }

        for fw in frameworks_to_check:
            fw_result = await self._check_framework(fw, configuration)
            results["frameworks"][fw] = fw_result

        # Calculate overall compliance
        compliance_scores = [
            fw_result.get("compliance_score", 0.0)
            for fw_result in results["frameworks"].values()
        ]
        if compliance_scores:
            results["overall_compliance"] = sum(compliance_scores) / len(compliance_scores)

        # Generate gap analysis
        results["gaps"] = self._identify_gaps(results["frameworks"])

        # Generate recommendations
        results["recommendations"] = await self._generate_recommendations(
            results["gaps"], configuration
        )

        self.compliance_results[results["timestamp"]] = results
        return results

    async def _check_framework(
        self,
        framework: str,
        configuration: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Check compliance for a specific framework."""
        controls = ComplianceFramework.get_controls(framework)
        checked_controls = {}

        # Get RAG context for framework
        rag_context = self.rag_engine.get_context(
            query=f"{framework} compliance requirements",
            n_results=3,
        )

        # Check each control
        for control_id, control_desc in controls.items():
            control_result = await self._check_control(
                control_id, control_desc, framework, configuration, rag_context
            )
            checked_controls[control_id] = control_result

        # Calculate compliance score
        compliant_count = sum(
            1 for r in checked_controls.values() if r.get("compliant", False)
        )
        total_count = len(checked_controls)
        compliance_score = compliant_count / total_count if total_count > 0 else 0.0

        return {
            "framework": framework,
            "controls": checked_controls,
            "compliance_score": compliance_score,
            "compliant_controls": compliant_count,
            "total_controls": total_count,
        }

    async def _check_control(
        self,
        control_id: str,
        control_desc: str,
        framework: str,
        configuration: Dict[str, Any],
        rag_context: str,
    ) -> Dict[str, Any]:
        """Check a specific control."""
        prompt = f"""
Check if the following system configuration complies with {framework} control {control_id}: {control_desc}

CONTROL REQUIREMENT:
{control_desc}

SYSTEM CONFIGURATION:
{json.dumps(configuration, indent=2)}

COMPLIANCE GUIDANCE:
{rag_context}

Determine if the configuration is compliant with this control. Provide:
1. Compliance status (compliant/non-compliant/partial)
2. Evidence from the configuration
3. Any gaps or issues
4. Specific fix recommendations if non-compliant
"""

        try:
            analysis = await self.llm_client.generate(
                prompt=prompt,
                system_prompt=f"You are a {framework} compliance auditor. Provide detailed compliance assessment.",
            )

            # Parse compliance status from analysis
            compliant = self._parse_compliance_status(analysis)

            return {
                "control_id": control_id,
                "control_description": control_desc,
                "compliant": compliant,
                "analysis": analysis,
                "evidence": self._extract_evidence(configuration, control_id),
            }

        except Exception as e:
            logger.error(f"Control check failed for {control_id}: {str(e)}")
            return {
                "control_id": control_id,
                "control_description": control_desc,
                "compliant": False,
                "error": str(e),
            }

    def _parse_compliance_status(self, analysis: str) -> bool:
        """Parse compliance status from LLM analysis."""
        analysis_lower = analysis.lower()
        if "non-compliant" in analysis_lower or "not compliant" in analysis_lower:
            return False
        if "compliant" in analysis_lower and "non" not in analysis_lower:
            return True
        return False  # Default to non-compliant if unclear

    def _extract_evidence(self, configuration: Dict[str, Any], control_id: str) -> Dict[str, Any]:
        """Extract relevant evidence from configuration."""
        # Simple keyword matching for evidence
        evidence = {}
        config_str = json.dumps(configuration).lower()

        # Map control IDs to keywords
        if "access" in control_id.lower() or "AC" in control_id:
            if "authentication" in config_str or "authorization" in config_str:
                evidence["access_controls"] = "Found"
        if "encryption" in control_id.lower() or "cryptographic" in control_id.lower():
            if "ssl" in config_str or "tls" in config_str or "encrypt" in config_str:
                evidence["encryption"] = "Found"
        if "backup" in control_id.lower():
            if "backup" in config_str or "replication" in config_str:
                evidence["backup"] = "Found"
        if "monitoring" in control_id.lower() or "SI-4" in control_id:
            if "logging" in config_str or "monitoring" in config_str:
                evidence["monitoring"] = "Found"

        return evidence

    def _identify_gaps(self, framework_results: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify compliance gaps."""
        gaps = []

        for framework, result in framework_results.items():
            controls = result.get("controls", {})
            for control_id, control_result in controls.items():
                if not control_result.get("compliant", False):
                    gaps.append({
                        "framework": framework,
                        "control_id": control_id,
                        "control_description": control_result.get("control_description", ""),
                        "issue": control_result.get("analysis", ""),
                    })

        return gaps

    async def _generate_recommendations(
        self,
        gaps: List[Dict[str, Any]],
        configuration: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate fix recommendations for gaps."""
        if not gaps:
            return []

        prompt = f"""
Based on the following compliance gaps, provide specific, actionable recommendations to fix them.

COMPLIANCE GAPS:
{json.dumps(gaps, indent=2)}

CURRENT CONFIGURATION:
{json.dumps(configuration, indent=2)}

For each gap, provide:
1. Specific configuration changes needed
2. Code examples or commands if applicable
3. Priority level (high/medium/low)
4. Estimated effort to implement
"""

        try:
            recommendations_text = await self.llm_client.generate(
                prompt=prompt,
                system_prompt="You are a compliance remediation expert. Provide clear, actionable recommendations with code examples.",
            )

            # Parse recommendations
            recommendations = self._parse_recommendations(recommendations_text, gaps)

            return recommendations

        except Exception as e:
            logger.error(f"Failed to generate recommendations: {str(e)}")
            return []

    def _parse_recommendations(
        self,
        recommendations_text: str,
        gaps: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Parse recommendations from text."""
        recommendations = []

        lines = recommendations_text.split("\n")
        current_rec = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Detect recommendation headers
            if line[0].isdigit() or line.startswith(("-", "*")):
                if current_rec:
                    recommendations.append(current_rec)

                current_rec = {
                    "gap": gaps[len(recommendations)] if len(recommendations) < len(gaps) else {},
                    "recommendation": line.lstrip("0123456789.-* ").strip(),
                    "priority": "medium",
                    "effort": "unknown",
                }
            elif current_rec:
                if "priority" in line.lower():
                    if "high" in line.lower():
                        current_rec["priority"] = "high"
                    elif "low" in line.lower():
                        current_rec["priority"] = "low"
                elif "effort" in line.lower() or "time" in line.lower():
                    current_rec["effort"] = line
                else:
                    current_rec["recommendation"] += " " + line

        if current_rec:
            recommendations.append(current_rec)

        return recommendations

    async def generate_compliance_report(
        self,
        compliance_results: Dict[str, Any],
        format: str = "json",
    ) -> str:
        """
        Generate compliance report.

        Args:
            compliance_results: Compliance check results
            format: Report format (json, markdown)

        Returns:
            Compliance report
        """
        if format == "json":
            return json.dumps(compliance_results, indent=2)

        # Generate markdown report
        report = f"""# Compliance Report

Generated: {compliance_results.get('timestamp', 'N/A')}

## Overall Compliance Score

**{compliance_results.get('overall_compliance', 0.0) * 100:.1f}%**

## Framework Compliance

"""

        for framework, fw_result in compliance_results.get("frameworks", {}).items():
            score = fw_result.get("compliance_score", 0.0) * 100
            compliant = fw_result.get("compliant_controls", 0)
            total = fw_result.get("total_controls", 0)

            report += f"""### {framework}

- Compliance Score: {score:.1f}%
- Compliant Controls: {compliant}/{total}

"""

        # Add gaps section
        gaps = compliance_results.get("gaps", [])
        if gaps:
            report += "## Compliance Gaps\n\n"
            for gap in gaps:
                report += f"""- **{gap.get('framework')} - {gap.get('control_id')}**: {gap.get('control_description', '')}\n"""

        # Add recommendations
        recommendations = compliance_results.get("recommendations", [])
        if recommendations:
            report += "\n## Recommendations\n\n"
            for rec in recommendations:
                report += f"""### {rec.get('recommendation', 'N/A')}\n\n"""
                report += f"**Priority**: {rec.get('priority', 'medium')}\n\n"
                report += f"**Effort**: {rec.get('effort', 'unknown')}\n\n"

        return report

    async def get_summary(self) -> Dict[str, Any]:
        """
        Get agent summary.

        Returns:
            Summary dictionary
        """
        return {
            "status": "active",
            "frameworks": self.frameworks,
            "total_checks": len(self.compliance_results),
            "last_check": max(self.compliance_results.keys()) if self.compliance_results else None,
        }

