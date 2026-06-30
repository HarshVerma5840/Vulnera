import os

# ZAP API Settings
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "5ueuakk9507bcasp8kduqmt1ri")
ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = os.getenv("ZAP_PORT", "8090")

# Target Application Settings
TARGET_URL = os.getenv("TARGET_URL", "http://demo.testfire.net")

# Reporting Settings
REPORT_PATH = os.getenv("REPORT_PATH", "zap_report.json")

# --- NEW ---
# Scan Mode Settings
SCAN_MODE = os.getenv("SCAN_MODE", "quick") # "quick" or "full"
