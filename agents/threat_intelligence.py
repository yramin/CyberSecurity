"""
Threat Intelligence Agent for IOC checking, CVE queries, and MITRE ATT&CK mapping.
Integrates with VirusTotal API and NVD API.
"""

import asyncio
import hashlib
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from core.llm_client import LLMClient
from core.rag_engine import RAGEngine

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """Client for VirusTotal API."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15  # 4 requests per minute = 15 seconds between requests
        self.last_request_time = 0.0

    async def _rate_limit(self):
        """Enforce rate limiting."""
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = asyncio.get_event_loop().time()

    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against VirusTotal.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            VirusTotal analysis results
        """
        await self._rate_limit()

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "API key not configured"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/files/{file_hash}",
                    headers={"x-apikey": self.api_key},
                    timeout=30.0,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"VirusTotal API error: {e.response.status_code}")
            return {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal check failed: {str(e)}")
            return {"error": str(e)}

    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL against VirusTotal.

        Args:
            url: URL to check

        Returns:
            VirusTotal analysis results
        """
        await self._rate_limit()

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "API key not configured"}

        try:
            # First, get URL ID
            url_id = hashlib.sha256(url.encode()).hexdigest()

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers={"x-apikey": self.api_key},
                    timeout=30.0,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # URL not in database, submit for analysis
                return await self._submit_url(url)
            logger.error(f"VirusTotal API error: {e.response.status_code}")
            return {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal URL check failed: {str(e)}")
            return {"error": str(e)}

    async def _submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/urls",
                    headers={"x-apikey": self.api_key},
                    data={"url": url},
                    timeout=30.0,
                )
                response.raise_for_status()
                return {"status": "submitted", "url": url}
        except Exception as e:
            logger.error(f"Failed to submit URL: {str(e)}")
            return {"error": str(e)}

    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address against VirusTotal.

        Args:
            ip_address: IP address to check

        Returns:
            VirusTotal analysis results
        """
        await self._rate_limit()

        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {"error": "API key not configured"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/ip_addresses/{ip_address}",
                    headers={"x-apikey": self.api_key},
                    timeout=30.0,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"VirusTotal API error: {e.response.status_code}")
            return {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal IP check failed: {str(e)}")
            return {"error": str(e)}


class NVDClient:
    """Client for NVD (National Vulnerability Database) API."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (optional but recommended)
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY", "")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.rate_limit_delay = 0.6  # 50 requests per 30 seconds = 0.6 seconds between requests
        self.last_request_time = 0.0

    async def _rate_limit(self):
        """Enforce rate limiting."""
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = asyncio.get_event_loop().time()

    async def get_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Get CVE details.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            CVE details
        """
        await self._rate_limit()

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}?cveId={cve_id}",
                    headers=headers,
                    timeout=30.0,
                )
                response.raise_for_status()
                data = response.json()
                if data.get("vulnerabilities"):
                    return data["vulnerabilities"][0]
                return {}
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error: {e.response.status_code}")
            return {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            logger.error(f"NVD CVE lookup failed: {str(e)}")
            return {"error": str(e)}

    async def search_cves(
        self,
        keyword: str,
        cvss_v3_severity: Optional[str] = None,
        results_per_page: int = 20,
    ) -> Dict[str, Any]:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search keyword
            cvss_v3_severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            results_per_page: Number of results per page

        Returns:
            Search results
        """
        await self._rate_limit()

        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            params = {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page,
            }
            if cvss_v3_severity:
                params["cvssV3Severity"] = cvss_v3_severity

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.base_url,
                    headers=headers,
                    params=params,
                    timeout=30.0,
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"NVD search failed: {str(e)}")
            return {"error": str(e)}


class ThreatIntelligenceAgent:
    """Threat Intelligence Agent for IOC checking and CVE queries."""

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        rag_engine: Optional[RAGEngine] = None,
        virustotal_api_key: Optional[str] = None,
        nvd_api_key: Optional[str] = None,
    ):
        """
        Initialize threat intelligence agent.

        Args:
            llm_client: LLM client for analysis
            rag_engine: RAG engine for context
            virustotal_api_key: VirusTotal API key
            nvd_api_key: NVD API key
        """
        self.llm_client = llm_client
        self.rag_engine = rag_engine
        self.vt_client = VirusTotalClient(virustotal_api_key)
        self.nvd_client = NVDClient(nvd_api_key)
        self.ioc_cache: Dict[str, Dict[str, Any]] = {}
        self.mitre_techniques: Dict[str, Any] = {}

    def _load_mitre_techniques(self, file_path: Optional[str] = None):
        """Load MITRE ATT&CK techniques."""
        # This would load from a JSON file
        # For now, we'll use a simple mapping
        self.mitre_techniques = {
            "T1059": "Command and Scripting Interpreter",
            "T1071": "Application Layer Protocol",
            "T1566": "Phishing",
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
        }

    async def check_ioc(self, ioc: str, ioc_type: str = "auto") -> Dict[str, Any]:
        """
        Check Indicator of Compromise (IOC).

        Args:
            ioc: IOC value (hash, IP, URL, domain)
            ioc_type: Type of IOC (auto, hash, ip, url, domain)

        Returns:
            IOC analysis results
        """
        # Auto-detect IOC type
        if ioc_type == "auto":
            if len(ioc) == 32 and all(c in "0123456789abcdefABCDEF" for c in ioc):
                ioc_type = "hash"
            elif len(ioc) == 40 and all(c in "0123456789abcdefABCDEF" for c in ioc):
                ioc_type = "hash"
            elif len(ioc) == 64 and all(c in "0123456789abcdefABCDEF" for c in ioc):
                ioc_type = "hash"
            elif ioc.startswith("http://") or ioc.startswith("https://"):
                ioc_type = "url"
            elif "." in ioc and not ioc.startswith("http"):
                # Could be IP or domain
                parts = ioc.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    ioc_type = "ip"
                else:
                    ioc_type = "domain"
            else:
                ioc_type = "unknown"

        # Check cache
        cache_key = f"{ioc_type}:{ioc}"
        if cache_key in self.ioc_cache:
            return self.ioc_cache[cache_key]

        result = {
            "ioc": ioc,
            "type": ioc_type,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": {},
        }

        # Check with VirusTotal
        if ioc_type == "hash":
            vt_result = await self.vt_client.check_hash(ioc)
            result["sources"]["virustotal"] = vt_result
        elif ioc_type == "url":
            vt_result = await self.vt_client.check_url(ioc)
            result["sources"]["virustotal"] = vt_result
        elif ioc_type == "ip":
            vt_result = await self.vt_client.check_ip(ioc)
            result["sources"]["virustotal"] = vt_result

        # Calculate risk score
        result["risk_score"] = self._calculate_risk_score(result)

        # Cache result
        self.ioc_cache[cache_key] = result

        return result

    def _calculate_risk_score(self, ioc_result: Dict[str, Any]) -> float:
        """
        Calculate risk score for IOC.

        Args:
            ioc_result: IOC analysis result

        Returns:
            Risk score (0-1)
        """
        risk_score = 0.0
        vt_data = ioc_result.get("sources", {}).get("virustotal", {})

        if "error" in vt_data:
            return 0.5  # Unknown risk

        # Check VirusTotal stats
        if "data" in vt_data:
            data = vt_data["data"]
            attributes = data.get("attributes", {})

            # Check malicious detections
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())

            if total > 0:
                risk_score = min(1.0, malicious / total)

        return risk_score

    async def get_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """
        Get CVE information.

        Args:
            cve_id: CVE identifier

        Returns:
            CVE information
        """
        result = await self.nvd_client.get_cve(cve_id)

        if "error" in result:
            return result

        # Extract key information
        cve_info = {
            "cve_id": cve_id,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if "cve" in result:
            cve_data = result["cve"]
            cve_info["description"] = cve_data.get("descriptions", [{}])[0].get("value", "")
            cve_info["published"] = cve_data.get("published", "")
            cve_info["modified"] = cve_data.get("lastModified", "")

            # Extract CVSS scores
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                cve_info["cvss_v3"] = {
                    "base_score": cvss.get("baseScore"),
                    "severity": cvss.get("baseSeverity"),
                    "vector": cvss.get("vectorString"),
                }

        return cve_info

    async def search_cves_by_keyword(self, keyword: str, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search keyword
            severity: Optional severity filter

        Returns:
            List of CVE information
        """
        results = await self.nvd_client.search_cves(keyword, cvss_v3_severity=severity)

        if "error" in results:
            return []

        cves = []
        vulnerabilities = results.get("vulnerabilities", [])

        for vuln in vulnerabilities[:10]:  # Limit to 10 results
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            cve_info = await self.get_cve_info(cve_id)
            cves.append(cve_info)

        return cves

    async def map_to_mitre_attack(self, technique_id: str) -> Dict[str, Any]:
        """
        Map to MITRE ATT&CK technique.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1059)

        Returns:
            Technique information
        """
        if not self.mitre_techniques:
            self._load_mitre_techniques()

        technique_info = {
            "technique_id": technique_id,
            "name": self.mitre_techniques.get(technique_id, "Unknown"),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Query RAG for more context
        if self.rag_engine:
            context = self.rag_engine.get_context(
                query=f"MITRE ATT&CK technique {technique_id}",
                n_results=3,
            )
            technique_info["context"] = context

        return technique_info

    async def enrich_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich threat data with intelligence.

        Args:
            threat_data: Threat data to enrich

        Returns:
            Enriched threat data
        """
        enriched = threat_data.copy()

        # Extract IOCs
        iocs = threat_data.get("iocs", [])
        enriched_iocs = []

        for ioc in iocs:
            ioc_result = await self.check_ioc(ioc)
            enriched_iocs.append(ioc_result)

        enriched["iocs"] = enriched_iocs

        # Map to MITRE ATT&CK if technique IDs provided
        techniques = threat_data.get("mitre_techniques", [])
        enriched_techniques = []

        for tech_id in techniques:
            tech_info = await self.map_to_mitre_attack(tech_id)
            enriched_techniques.append(tech_info)

        enriched["mitre_techniques"] = enriched_techniques

        # Calculate overall risk score
        risk_scores = [ioc.get("risk_score", 0.0) for ioc in enriched_iocs]
        enriched["overall_risk_score"] = max(risk_scores) if risk_scores else 0.0

        return enriched

    async def get_summary(self) -> Dict[str, Any]:
        """
        Get agent summary.

        Returns:
            Summary dictionary
        """
        return {
            "status": "active",
            "ioc_cache_size": len(self.ioc_cache),
            "virustotal_configured": bool(self.vt_client.api_key),
            "nvd_configured": bool(self.nvd_client.api_key),
            "mitre_techniques_loaded": len(self.mitre_techniques),
        }

