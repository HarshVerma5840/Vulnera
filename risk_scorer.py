"""
risk_scorer.py — Phase 2: Composite Risk Scoring

Calculates a comprehensive 0.0-1.0 risk score by combining:
1. CVSS Severity (NVD API)
2. EPSS Probability (FIRST.org API)
3. Endpoint Criticality (Phase 1)
4. Tool Confidence
5. Cross-Tool Amplification
"""

import os
import requests
from cache_manager import redis_cache

class RiskScorer:
    """
    Computes composite risk scores by combining external threat intel
    with internal context and scanner confidence.
    """

    # NVD API configuration
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.getenv("NVD_API_KEY", None)  # Optional, for higher rate limits

    # EPSS API configuration
    EPSS_API_BASE = "https://api.first.org/data/v1/epss"

    # Ports that indicate exposed databases
    EXPOSED_DB_PORTS = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        5984: "CouchDB",
    }

    # Ports that indicate exposed admin services
    ADMIN_SERVICE_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP Alt",
        8443: "HTTPS Alt",
    }

    # Composite formula weights (must sum to 1.0)
    WEIGHT_CVSS = 0.35
    WEIGHT_EPSS = 0.25
    WEIGHT_ENDPOINT = 0.20
    WEIGHT_CONFIDENCE = 0.10
    WEIGHT_AMPLIFICATION = 0.10

    # Risk level thresholds
    LEVEL_CRITICAL = 0.85
    LEVEL_HIGH = 0.65
    LEVEL_MEDIUM = 0.40

    def __init__(self):
        self._endpoint_scorer = None  # Lazy loaded if needed

    @redis_cache(prefix="cvss", ttl=604800, cache_errors=False)
    def fetch_cvss(self, cve_id: str) -> float:
        """
        Fetch CVSS v3.1 base score from NVD API.
        Returns normalised score (0.0-1.0) by dividing by 10.
        Uses @lru_cache to avoid repeated API calls for the same CVE.
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return 0.5  # Default baseline for non-CVE alerts

        try:
            headers = {}
            if RiskScorer.NVD_API_KEY:
                headers["apiKey"] = RiskScorer.NVD_API_KEY

            response = requests.get(
                RiskScorer.NVD_API_BASE,
                params={"cveId": cve_id},
                headers=headers,
                timeout=5  # Fast timeout so scan doesn't hang
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return 0.5

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            # Try CVSS v3.1 first, then v3.0
            for version_key in ["cvssMetricV31", "cvssMetricV30"]:
                cvss_list = metrics.get(version_key, [])
                if cvss_list:
                    base_score = cvss_list[0].get("cvssData", {}).get("baseScore", 5.0)
                    return round(base_score / 10.0, 4)  # Normalise to 0-1

            # Fallback to CVSS v2
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                base_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 5.0)
                return round(base_score / 10.0, 4)

            return 0.5  # No CVSS data found

        except requests.RequestException as e:
            # Silently fallback so scanner doesn't break
            # print(f"[!] NVD API error for {cve_id}: {e}")
            return 0.5
        except Exception:
            return 0.5

    @redis_cache(prefix="epss", ttl=86400, cache_errors=False)
    def fetch_epss(self, cve_id: str) -> float:
        """
        Fetch EPSS score (exploitation probability) from FIRST.org API.
        Returns 0.0-1.0 probability score.
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return 0.1  # Low probability default for non-CVEs

        try:
            response = requests.get(
                RiskScorer.EPSS_API_BASE,
                params={"cve": cve_id},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()

            epss_data = data.get("data", [])
            if epss_data:
                epss_score = float(epss_data[0].get("epss", 0.1))
                return round(epss_score, 4)

            return 0.1

        except requests.RequestException as e:
            # print(f"[!] EPSS API error for {cve_id}: {e}")
            return 0.1
        except Exception:
            return 0.1

    def _normalise_confidence(self, alert: dict) -> float:
        """Convert tool confidence levels to a 0.0-1.0 float."""
        confidence_map = {
            "High": 0.9,
            "Medium": 0.6,
            "Low": 0.3,
            "Informational": 0.1,
            "Confirmed": 1.0,
        }

        source = alert.get("source", "")
        confidence_str = alert.get("confidence", "Medium")
        base = confidence_map.get(confidence_str, 0.5)

        # Nmap service detection is generally very reliable
        if source == "nmap":
            base = max(base, 0.7)

        return base

    def score_alert(self, alert: dict, endpoint_score: float = 0.5, amplification: float = 1.0) -> dict:
        """
        Compute the composite risk score for a single unified alert.
        """
        cve_id = alert.get("cve_id")
        cwe_id = alert.get("cwe_id")

        # Fetch external scores (these will be instant if cached)
        cvss_normalised = self.fetch_cvss(cve_id)
        epss_score = self.fetch_epss(cve_id)
        confidence = self._normalise_confidence(alert)

        # Normalise amplification (1.0 - 1.5) to a 0.0 - 1.0 range for the formula
        amp_normalised = min((amplification - 1.0) * 2.0, 1.0)

        # Base composite formula
        risk_score = (
            self.WEIGHT_CVSS * cvss_normalised +
            self.WEIGHT_EPSS * epss_score +
            self.WEIGHT_ENDPOINT * endpoint_score +
            self.WEIGHT_CONFIDENCE * confidence +
            self.WEIGHT_AMPLIFICATION * amp_normalised
        )

        # Apply amplification as a final multiplier (caps at 1.0)
        risk_score = min(1.0, risk_score * amplification)

        # Determine textual risk level
        if risk_score >= self.LEVEL_CRITICAL:
            risk_level = "CRITICAL"
        elif risk_score >= self.LEVEL_HIGH:
            risk_level = "HIGH"
        elif risk_score >= self.LEVEL_MEDIUM:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_score": round(risk_score, 4),
            "risk_level": risk_level,
            "components": {
                "cvss": round(cvss_normalised, 4),
                "cvss_raw": round(cvss_normalised * 10, 1),
                "epss": round(epss_score, 4),
                "endpoint_criticality": round(endpoint_score, 4),
                "tool_confidence": round(confidence, 4),
                "amplification": amplification
            },
            "enrichment": {
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "cvss_source": "NVD_V31" if cve_id else None,
                "epss_source": "FIRST.org" if cve_id else None
            }
        }

    def compute_amplification(self, alert: dict, nmap_results: list, all_alerts: list = None) -> float:
        """
        Compute cross-tool signal amplification factor.
        """
        amplification = 1.0
        alert_host = alert.get("host", "")
        alert_type = alert.get("type", "")

        # Extract all open ports for the alert's host
        open_ports = set()
        open_db_ports = set()
        open_admin_ports = set()

        for host_data in nmap_results:
            if host_data.get("host") == alert_host:
                for port_info in host_data.get("ports", []):
                    if port_info.get("state") == "open":
                        port = port_info.get("port")
                        open_ports.add(port)
                        if port in self.EXPOSED_DB_PORTS:
                            open_db_ports.add(port)
                        if port in self.ADMIN_SERVICE_PORTS:
                            open_admin_ports.add(port)

        # Rule 1: Exposed DB + web vulnerability → 1.30x
        if open_db_ports and alert_type in (
            "sqli", "sqli_blind", "sqli_blind_time",
            "command_injection", "remote_code_execution",
            "path_traversal", "remote_file_inclusion"
        ):
            amplification = max(amplification, 1.30)

        # Rule 2: SSL issues + web vulns on same host → 1.20x
        if all_alerts:
            ssl_issues_on_host = any(
                a.get("host") == alert_host and "ssl" in a.get("type", "").lower()
                for a in all_alerts
            )
            web_vuln = alert.get("source") == "zap" and alert.get("risk") in ("High", "Medium")
            if ssl_issues_on_host and web_vuln:
                amplification = max(amplification, 1.20)

        # Rule 3: Both tools flag same service → 1.15x
        if alert.get("source") == "zap" and open_ports:
            amplification = max(amplification, 1.15)

        # Rule 4: Multiple high-severity alerts on same endpoint → 1.10x
        if all_alerts:
            same_endpoint_high = sum(
                1 for a in all_alerts
                if a.get("path") == alert.get("path")
                and a.get("risk") in ("High", "Critical")
                and a.get("alert_id") != alert.get("alert_id")
            )
            if same_endpoint_high >= 2:
                amplification = max(amplification, 1.10)

        # Cap at 1.5
        return min(amplification, 1.5)

    def compute_all_amplifications(self, alerts: list, nmap_results: list) -> dict:
        """
        Compute amplification factors for all alerts.
        """
        amplifications = {}
        for alert in alerts:
            alert_id = alert.get("alert_id", "")
            factor = self.compute_amplification(alert, nmap_results, all_alerts=alerts)
            amplifications[alert_id] = factor

        return amplifications

    def score_all(self, alerts: list, endpoint_scores: dict, amplifications: dict) -> list:
        """
        Compute risk scores for a list of unified alerts and update them in place.
        """
        for alert in alerts:
            alert_id = alert.get("alert_id", "")
            ep_score = endpoint_scores.get(alert_id, 0.5)
            amp = amplifications.get(alert_id, 1.0)
            
            score_data = self.score_alert(alert, endpoint_score=ep_score, amplification=amp)
            alert.update(score_data)
            
        return alerts
