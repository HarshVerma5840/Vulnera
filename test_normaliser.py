"""
Test script for normaliser.py — Phase 0 verification.

Tests against:
1. Synthetic ZAP and Nmap data (unit tests)
2. Real scan data from previous Vulnera scans (integration test)
"""

import json
import os
import sys

# Fix Windows console encoding
sys.stdout.reconfigure(encoding='utf-8')

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(__file__))

from normaliser import (
    normalise_zap_alert,
    normalise_nmap_finding,
    normalise_all,
    _map_zap_plugin_to_type,
    _classify_nmap_port,
)


def test_zap_cwe_extraction():
    """cweid='-1' → None, cweid='79' → 'CWE-79'"""
    # CWE "-1" should become None
    alert_no_cwe = {"pluginId": "10112", "name": "Test", "url": "http://x.com", "cweid": "-1"}
    result = normalise_zap_alert(alert_no_cwe)
    assert result["cwe_id"] is None, f"Expected None, got {result['cwe_id']}"

    # CWE "0" should also become None
    alert_zero_cwe = {"pluginId": "10112", "name": "Test", "url": "http://x.com", "cweid": "0"}
    result = normalise_zap_alert(alert_zero_cwe)
    assert result["cwe_id"] is None, f"Expected None for cweid=0, got {result['cwe_id']}"

    # CWE "79" should become "CWE-79"
    alert_real_cwe = {"pluginId": "40012", "name": "XSS", "url": "http://x.com", "cweid": "79"}
    result = normalise_zap_alert(alert_real_cwe)
    assert result["cwe_id"] == "CWE-79", f"Expected CWE-79, got {result['cwe_id']}"

    print("  ✓ CWE extraction: cweid=-1 → None, cweid=79 → CWE-79")


def test_zap_plugin_mapping():
    """Known plugin IDs map correctly."""
    assert _map_zap_plugin_to_type("40012", "") == "xss_reflected"
    assert _map_zap_plugin_to_type("40018", "") == "sqli"
    assert _map_zap_plugin_to_type("90019", "") == "command_injection"
    assert _map_zap_plugin_to_type("10112", "") == "session_management"

    # Unknown plugin falls back to slugified name
    fallback = _map_zap_plugin_to_type("99999", "My Custom Alert Name")
    assert fallback == "my_custom_alert_name", f"Expected 'my_custom_alert_name', got '{fallback}'"

    print("  ✓ Plugin mapping: known IDs map correctly, unknown falls back to slug")


def test_zap_path_extraction():
    """URL path is correctly extracted."""
    alert = {
        "pluginId": "40012",
        "name": "XSS",
        "url": "http://demo.testfire.net/search?q=test&page=1",
        "cweid": "79",
        "method": "GET",
    }
    result = normalise_zap_alert(alert)
    assert result["path"] == "/search", f"Expected '/search', got '{result['path']}'"
    assert result["host"] == "demo.testfire.net", f"Expected 'demo.testfire.net', got '{result['host']}'"
    assert result["method"] == "GET"

    print("  ✓ Path extraction: URL → path, host, method")


def test_zap_alert_id_uniqueness():
    """Different alerts get different IDs."""
    alert1 = {"pluginId": "40012", "name": "XSS", "url": "http://x.com/a", "param": "q"}
    alert2 = {"pluginId": "40012", "name": "XSS", "url": "http://x.com/b", "param": "q"}
    alert3 = {"pluginId": "40012", "name": "XSS", "url": "http://x.com/a", "param": "id"}

    id1 = normalise_zap_alert(alert1)["alert_id"]
    id2 = normalise_zap_alert(alert2)["alert_id"]
    id3 = normalise_zap_alert(alert3)["alert_id"]

    assert id1 != id2, "Different URLs should produce different IDs"
    assert id1 != id3, "Different params should produce different IDs"
    assert id1.startswith("zap_40012_"), f"ID should start with 'zap_40012_', got '{id1}'"

    print("  ✓ Alert ID uniqueness: different URL/param → different IDs")


def test_zap_all_fields_present():
    """Every required field exists in the output."""
    alert = {
        "pluginId": "40018", "name": "SQL Injection", "url": "http://x.com/login",
        "method": "POST", "cweid": "89", "confidence": "High", "risk": "High",
        "evidence": "' OR 1=1--", "description": "SQL Injection found.",
        "solution": "Use parameterised queries.", "tags": {},
    }
    result = normalise_zap_alert(alert)

    required_fields = [
        "source", "alert_id", "url", "path", "method", "host",
        "type", "confidence", "risk", "cve_id", "cwe_id",
        "evidence", "description", "solution", "raw",
    ]
    for field in required_fields:
        assert field in result, f"Missing field: {field}"

    assert result["source"] == "zap"
    assert result["raw"] is alert  # Raw data preserved

    print("  ✓ All required fields present in ZAP output")


def test_nmap_db_port():
    """Port 3306 (MySQL) classifies as exposed_database with High risk."""
    port_info = {"port": 3306, "state": "open", "service": "mysql", "product": "", "version": ""}
    result = normalise_nmap_finding(port_info, "65.61.137.117")

    assert result["type"] == "exposed_database", f"Expected 'exposed_database', got '{result['type']}'"
    assert result["risk"] == "High", f"Expected 'High', got '{result['risk']}'"
    assert result["source"] == "nmap"
    assert result["host"] == "65.61.137.117"
    assert "mysql" in result["description"].lower()

    print("  ✓ Nmap DB port: 3306/open → exposed_database, High risk")


def test_nmap_web_port():
    """Port 80 (HTTP) classifies as web_service with Informational risk."""
    port_info = {
        "port": 80, "state": "open", "service": "http",
        "product": "Apache Tomcat/Coyote JSP engine", "version": "1.1",
    }
    result = normalise_nmap_finding(port_info, "65.61.137.117")

    assert result["type"] == "web_service", f"Expected 'web_service', got '{result['type']}'"
    assert result["risk"] == "Informational"

    print("  ✓ Nmap web port: 80/open → web_service, Informational")


def test_nmap_filtered_port():
    """Filtered ports get Informational risk."""
    port_info = {"port": 22, "state": "filtered", "service": "ssh", "product": "", "version": ""}
    result = normalise_nmap_finding(port_info, "10.0.0.1")

    assert result["type"] == "filtered_port"
    assert result["risk"] == "Informational"

    print("  ✓ Nmap filtered port: 22/filtered → filtered_port, Informational")


def test_nmap_admin_port():
    """Port 22 (SSH) when open classifies as exposed_admin_service."""
    port_info = {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.9"}
    result = normalise_nmap_finding(port_info, "10.0.0.1")

    assert result["type"] == "exposed_admin_service"
    assert result["risk"] == "Medium"

    print("  ✓ Nmap admin port: 22/open → exposed_admin_service, Medium")


def test_normalise_all_sorting():
    """normalise_all() returns alerts sorted by risk (High → Medium → Low → Info)."""
    zap_alerts = [
        {"pluginId": "10112", "name": "Session Mgmt", "url": "http://x.com", "risk": "Informational", "cweid": "-1"},
        {"pluginId": "40018", "name": "SQLi", "url": "http://x.com/login", "risk": "High", "cweid": "89"},
    ]
    nmap_results = [{"host": "1.2.3.4", "state": "up", "ports": [
        {"port": 80, "state": "open", "service": "http", "product": "", "version": ""},
        {"port": 3306, "state": "open", "service": "mysql", "product": "", "version": ""},
    ]}]

    results = normalise_all(zap_alerts, nmap_results)

    # Should be: High (SQLi) → High (MySQL) → Informational (Session) → Informational (HTTP)
    risks = [r["risk"] for r in results]
    expected_order = ["High", "High", "Informational", "Informational"]
    assert risks == expected_order, f"Expected {expected_order}, got {risks}"

    print("  ✓ normalise_all() sorts by risk: High → Medium → Low → Informational")


def test_normalise_all_count():
    """normalise_all() processes both ZAP and Nmap inputs."""
    zap_alerts = [
        {"pluginId": "40012", "name": "XSS", "url": "http://x.com/a", "cweid": "79", "risk": "High"},
        {"pluginId": "40018", "name": "SQLi", "url": "http://x.com/b", "cweid": "89", "risk": "High"},
    ]
    nmap_results = [{"host": "1.2.3.4", "state": "up", "ports": [
        {"port": 80, "state": "open", "service": "http", "product": "", "version": ""},
        {"port": 22, "state": "filtered", "service": "ssh", "product": "", "version": ""},
        {"port": 443, "state": "open", "service": "ssl", "product": "", "version": ""},
    ]}]

    results = normalise_all(zap_alerts, nmap_results)
    assert len(results) == 5, f"Expected 5 alerts (2 ZAP + 3 Nmap), got {len(results)}"

    zap_count = sum(1 for r in results if r["source"] == "zap")
    nmap_count = sum(1 for r in results if r["source"] == "nmap")
    assert zap_count == 2
    assert nmap_count == 3

    print("  ✓ normalise_all() processes both sources: 2 ZAP + 3 Nmap = 5 total")


def test_with_real_scan_data():
    """Integration test with real scan data from a previous Vulnera scan."""
    report_path = os.path.join("zap", "vulnscan_625822c30be643e0_combined_report.json")

    if not os.path.exists(report_path):
        print("  ⊘ Skipped: No real scan data found (run a scan first)")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    # Extract raw data
    nmap_results = report.get("nmap_results", [])
    zap_raw_alerts = []
    for zap_report in report.get("zap_reports", []):
        if zap_report.get("success") and zap_report.get("data"):
            zap_raw_alerts.extend(zap_report["data"].get("raw_alerts", []))

    print(f"    Found {len(zap_raw_alerts)} raw ZAP alerts, {len(nmap_results)} Nmap hosts")

    # Normalise everything
    unified = normalise_all(zap_raw_alerts, nmap_results)

    print(f"    Normalised into {len(unified)} unified alerts")

    # Verify all alerts have required fields
    required_fields = [
        "source", "alert_id", "url", "path", "method", "host",
        "type", "confidence", "risk", "cve_id", "cwe_id",
        "evidence", "description", "solution", "raw",
    ]
    missing_count = 0
    for alert in unified:
        for field in required_fields:
            if field not in alert:
                print(f"    [!] Alert {alert.get('alert_id', '?')} missing field: {field}")
                missing_count += 1

    assert missing_count == 0, f"{missing_count} missing fields found"

    # Print risk distribution
    from collections import Counter
    risk_dist = Counter(a["risk"] for a in unified)
    type_dist = Counter(a["type"] for a in unified)
    source_dist = Counter(a["source"] for a in unified)

    print(f"    Risk distribution: {dict(risk_dist)}")
    print(f"    Source distribution: {dict(source_dist)}")
    print(f"    Top 5 alert types: {dict(type_dist.most_common(5))}")

    # Show a few sample alerts
    print("\n    Sample normalised alerts:")
    for alert in unified[:3]:
        print(f"      [{alert['risk']:>13}] [{alert['source']:>4}] {alert['type']:<30} {alert['url'][:60]}")

    print(f"\n  ✓ Real scan data: {len(unified)} alerts normalised with 0 missing fields")


# =============================================================================
# Run all tests
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Phase 0 — Normaliser Tests")
    print("=" * 60)

    tests = [
        ("ZAP CWE extraction", test_zap_cwe_extraction),
        ("ZAP plugin mapping", test_zap_plugin_mapping),
        ("ZAP path extraction", test_zap_path_extraction),
        ("ZAP alert ID uniqueness", test_zap_alert_id_uniqueness),
        ("ZAP all fields present", test_zap_all_fields_present),
        ("Nmap DB port classification", test_nmap_db_port),
        ("Nmap web port classification", test_nmap_web_port),
        ("Nmap filtered port classification", test_nmap_filtered_port),
        ("Nmap admin port classification", test_nmap_admin_port),
        ("normalise_all sorting", test_normalise_all_sorting),
        ("normalise_all count", test_normalise_all_count),
        ("Real scan data integration", test_with_real_scan_data),
    ]

    passed = 0
    failed = 0

    for name, test_fn in tests:
        try:
            print(f"\n[TEST] {name}")
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)
