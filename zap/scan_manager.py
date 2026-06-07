import json
import os
from config import TARGET_URL, ZAP_API_KEY, ZAP_HOST, ZAP_PORT, REPORT_PATH
from scanner import ZAPScanManager

def main():
    scanner = ZAPScanManager(
        target=TARGET_URL,
        api_key=ZAP_API_KEY,
        zap_host=ZAP_HOST,
        zap_port=ZAP_PORT
    )

    results = scanner.run_full_scan()

    # Ensure the directory exists if a path is specified
    report_dir = os.path.dirname(REPORT_PATH)
    if report_dir and not os.path.exists(report_dir):
        os.makedirs(report_dir, exist_ok=True)

    with open(REPORT_PATH, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[+] Report saved to {REPORT_PATH}")

if __name__ == "__main__":
    main()