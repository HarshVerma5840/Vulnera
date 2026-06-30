"""
normaliser.py — Unified Alert Schema for Vulnera

Transforms raw ZAP alerts and Nmap port findings into a single,
consistent schema that all downstream intelligence modules (endpoint_scorer,
risk_scorer, cwe_lookup, feedback_loop) can consume.

This is the data contract for the entire AI intelligence layer.

Unified Alert Schema:
{
    "source": "zap" | "nmap",
    "alert_id": "zap_40012_abc123",
    "url": "http://example.com/login",
    "path": "/login",
    "method": "GET",
    "host": "example.com",
    "type": "xss_reflected",
    "confidence": "High",
    "risk": "High",
    "cve_id": "CVE-2024-XXXX" | None,
    "cwe_id": "CWE-79" | None,
    "evidence": "...",
    "description": "...",
    "solution": "...",
    "raw": { ... }
}
"""

from urllib.parse import urlparse
import hashlib


# =============================================================================
# ZAP Plugin ID → Normalised Alert Type Mapping
# =============================================================================
# Maps ZAP's numeric plugin IDs to human-readable, consistent type strings.
# This list covers the most common plugins. Unknown plugins fall back to
# a slugified version of the alert name.

ZAP_PLUGIN_TYPE_MAP = {
    # Injection attacks
    "40012": "xss_reflected",
    "40014": "xss_persistent",
    "40018": "sqli",
    "40016": "sqli_blind",
    "40017": "sqli_blind_time",
    "90019": "command_injection",
    "90020": "remote_code_execution",
    "90021": "xpath_injection",
    "90023": "xml_external_entity",
    "90024": "generic_padding_oracle",
    "6":     "path_traversal",
    "7":     "remote_file_inclusion",
    "40009": "server_side_include",
    "40028": "open_redirect",
    "40029": "trace_method",

    # Cookie / Session
    "10010": "cookie_no_httponly",
    "10011": "cookie_no_secure",
    "10054": "cookie_samesite",
    "10112": "session_management",

    # Headers / Configuration
    "10015": "autocomplete_enabled",
    "10016": "web_browser_xss_protection",
    "10017": "cross_domain_javascript",
    "10020": "x_frame_options",
    "10021": "x_content_type_options",
    "10035": "strict_transport_security",
    "10036": "server_version_leak",
    "10038": "content_security_policy",
    "10055": "content_security_policy_report",
    "10098": "cross_domain_misconfiguration",

    # Information Disclosure
    "10096": "timestamp_disclosure",
    "10097": "hash_disclosure",
    "10104": "user_agent_fuzzer",

    # CSRF
    "10202": "absence_of_anti_csrf",
}


# =============================================================================
# Nmap Port Classification Constants
# =============================================================================

# Ports that indicate exposed databases — high severity when open
DB_PORTS = {
    3306: "mysql",
    5432: "postgresql",
    1433: "mssql",
    27017: "mongodb",
    6379: "redis",
    9200: "elasticsearch",
    5984: "couchdb",
}

# Ports that indicate admin/sensitive services
ADMIN_PORTS = {
    22: "ssh",
    23: "telnet",
    3389: "rdp",
    5900: "vnc",
}


# =============================================================================
# Internal Helpers
# =============================================================================

def _map_zap_plugin_to_type(plugin_id: str, name: str) -> str:
    """
    Convert a ZAP plugin ID to a normalised alert type string.

    Falls back to a slugified version of the alert name if the plugin ID
    is not in our mapping dictionary.

    Args:
        plugin_id: ZAP plugin ID (e.g. "40012")
        name: ZAP alert name (e.g. "Cross Site Scripting (Reflected)")

    Returns:
        Normalised type string (e.g. "xss_reflected")
    """
    if plugin_id in ZAP_PLUGIN_TYPE_MAP:
        return ZAP_PLUGIN_TYPE_MAP[plugin_id]

    # Fallback: slugify the alert name
    # "Cross Site Scripting (Reflected)" → "cross_site_scripting_reflected"
    slug = name.lower()
    slug = slug.replace("(", "").replace(")", "").replace("-", "_")
    slug = slug.replace(" ", "_")
    # Remove consecutive underscores and trim
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug.strip("_")[:50]


def _classify_nmap_port(port: int, service: str, state: str) -> tuple:
    """
    Classify an Nmap port finding into a type and risk level.

    Args:
        port: Port number
        service: Service name from Nmap (e.g. "http", "mysql")
        state: Port state ("open", "filtered", "closed")

    Returns:
        Tuple of (alert_type: str, risk_level: str)
    """
    if state != "open":
        return ("filtered_port", "Informational")

    if port in DB_PORTS:
        return ("exposed_database", "High")
    if port in ADMIN_PORTS:
        return ("exposed_admin_service", "Medium")
    if "http" in service or "ssl" in service or "www" in service:
        return ("web_service", "Informational")

    return ("open_port", "Low")


# =============================================================================
# Public API
# =============================================================================

def normalise_zap_alert(alert: dict) -> dict:
    """
    Transform a single raw ZAP alert into the unified alert schema.

    Args:
        alert: Raw ZAP alert dict as returned by scanner.py's get_alerts().
               Expected fields: url, method, pluginId, cweid, confidence,
               risk, name, evidence, description, solution, tags, param, etc.

    Returns:
        Unified alert dict with consistent field names and types.

    Example:
        >>> raw = {"pluginId": "40012", "name": "XSS (Reflected)", "risk": "High",
        ...        "url": "http://example.com/search?q=test", "cweid": "79", ...}
        >>> normalise_zap_alert(raw)
        {"source": "zap", "type": "xss_reflected", "cwe_id": "CWE-79", ...}
    """
    url = alert.get("url", "")
    parsed = urlparse(url)

    # --- CWE extraction ---
    # ZAP uses "-1" when there is no CWE mapping (not None)
    cweid = alert.get("cweid", "-1")
    cwe_id = None
    if cweid and str(cweid) != "-1" and str(cweid) != "0":
        cwe_id = f"CWE-{cweid}"

    # --- CVE extraction from tags ---
    # Some ZAP alerts include CVE references in their tags dict
    tags = alert.get("tags", {})
    cve_id = None
    if isinstance(tags, dict):
        for tag_key in tags:
            if tag_key.upper().startswith("CVE-"):
                cve_id = tag_key.upper()
                break

    # --- Generate unique alert ID ---
    # Combination of pluginId + URL + param ensures uniqueness
    unique_str = f"{alert.get('pluginId', '')}_{url}_{alert.get('param', '')}"
    alert_hash = hashlib.md5(unique_str.encode()).hexdigest()[:8]
    plugin_id = alert.get("pluginId", "unknown")

    # --- Map alert type ---
    alert_type = _map_zap_plugin_to_type(
        plugin_id,
        alert.get("name", "Unknown Alert")
    )

    return {
        "source": "zap",
        "alert_id": f"zap_{plugin_id}_{alert_hash}",
        "url": url,
        "path": parsed.path or "/",
        "method": alert.get("method", "GET"),
        "host": parsed.hostname or "",
        "type": alert_type,
        "confidence": alert.get("confidence", "Low"),
        "risk": alert.get("risk", "Informational"),
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "evidence": alert.get("evidence", ""),
        "description": alert.get("description", ""),
        "solution": alert.get("solution", ""),
        "raw": alert,
    }


def normalise_nmap_finding(port_info: dict, host: str) -> dict:
    """
    Transform a single Nmap port finding into the unified alert schema.

    Args:
        port_info: Single port dict from nmap_manager.scan_host().
                   Expected fields: port, state, service, product, version.
        host: IP address or hostname of the scanned host.

    Returns:
        Unified alert dict.

    Example:
        >>> port = {"port": 3306, "state": "open", "service": "mysql", ...}
        >>> normalise_nmap_finding(port, "65.61.137.117")
        {"source": "nmap", "type": "exposed_database", "risk": "High", ...}
    """
    port = port_info.get("port", 0)
    state = port_info.get("state", "unknown")
    service = port_info.get("service", "").lower()
    product = port_info.get("product", "")
    version = port_info.get("version", "")

    # Classify the port
    alert_type, risk_level = _classify_nmap_port(port, service, state)

    # Build a human-readable evidence string
    service_desc = service
    if product:
        service_desc = f"{service} ({product}"
        if version:
            service_desc += f" {version}"
        service_desc += ")"

    evidence = f"Port {port} ({service_desc}) is {state}"

    # Build description based on classification
    if alert_type == "exposed_database":
        db_name = DB_PORTS.get(port, service)
        description = (
            f"Nmap detected an exposed {db_name} database service on port {port} "
            f"of host {host}. Publicly accessible database ports are a significant "
            f"security risk and can lead to data breaches."
        )
        solution = (
            f"Restrict access to port {port} using firewall rules. "
            f"Ensure {db_name} is not listening on public interfaces. "
            f"Use network segmentation and VPN for database access."
        )
    elif alert_type == "exposed_admin_service":
        svc_name = ADMIN_PORTS.get(port, service)
        description = (
            f"Nmap detected an exposed {svc_name} service on port {port} "
            f"of host {host}. Administrative services exposed to the internet "
            f"are common attack vectors."
        )
        solution = (
            f"Restrict {svc_name} access via firewall rules. "
            f"Use key-based authentication instead of passwords. "
            f"Consider using a VPN or bastion host for remote access."
        )
    elif alert_type == "web_service":
        description = (
            f"Nmap detected a web service on port {port} of host {host}: "
            f"{service_desc}."
        )
        solution = "Ensure the web server is patched and properly configured."
    elif alert_type == "filtered_port":
        description = (
            f"Port {port} ({service}) on host {host} is filtered. "
            f"A firewall or security device is blocking direct access."
        )
        solution = "No action required — filtered ports are not directly accessible."
    else:
        description = (
            f"Nmap detected an open port {port} running {service_desc} "
            f"on host {host}."
        )
        solution = (
            f"Review whether port {port} needs to be publicly accessible. "
            f"Close unnecessary ports and apply firewall rules."
        )

    return {
        "source": "nmap",
        "alert_id": f"nmap_{port}_{host}",
        "url": f"{host}:{port}",
        "path": "/",
        "method": "N/A",
        "host": host,
        "type": alert_type,
        "confidence": "High",  # Nmap service detection is reliable
        "risk": risk_level,
        "cve_id": None,
        "cwe_id": None,
        "evidence": evidence,
        "description": description,
        "solution": solution,
        "raw": port_info,
    }


def normalise_all(zap_alerts: list, nmap_results: list) -> list:
    """
    Batch normaliser: transforms all ZAP alerts and Nmap findings into
    a single list of unified alert dicts, sorted by risk severity.

    Args:
        zap_alerts: List of raw ZAP alert dicts (from scanner.get_alerts())
        nmap_results: List of host dicts (from nmap_manager.scan_host())
                      Each host has {"host": "...", "state": "...", "ports": [...]}

    Returns:
        List of unified alert dicts, sorted by risk level
        (Critical → High → Medium → Low → Informational)
    """
    unified = []

    # Normalise ZAP alerts
    for alert in zap_alerts:
        try:
            unified.append(normalise_zap_alert(alert))
        except Exception as e:
            print(f"[!] Failed to normalise ZAP alert: {e}")
            continue

    # Normalise Nmap findings
    for host_data in nmap_results:
        host = host_data.get("host", "")
        for port_info in host_data.get("ports", []):
            try:
                unified.append(normalise_nmap_finding(port_info, host))
            except Exception as e:
                print(f"[!] Failed to normalise Nmap finding: {e}")
                continue

    # Sort by risk severity (most severe first)
    RISK_ORDER = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }
    unified.sort(key=lambda a: RISK_ORDER.get(a.get("risk", "Informational"), 5))

    return unified
