from zapv2 import ZAPv2
import time
import json


class ZAPScanManager:
    def __init__(self, target, api_key="", zap_host="127.0.0.1", zap_port="8080"):
        self.target = target

        self.zap = ZAPv2(
            apikey=api_key,
            proxies={
                "http": f"http://{zap_host}:{zap_port}",
                "https": f"http://{zap_host}:{zap_port}",
            },
        )

    # 1. Spider crawl
    def spider(self):
        print("[*] Starting spider...")
        scan_id = self.zap.spider.scan(self.target)

        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)

        print("[+] Spider completed")

    # 2. Active scan (attack simulation)
    def active_scan(self):
        print("[*] Starting active scan...")
        scan_id = self.zap.ascan.scan(self.target)

        while int(self.zap.ascan.status(scan_id)) < 100:
            print(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("[+] Active scan completed")

    # 3. Get alerts
    def get_alerts(self):
        alerts = self.zap.core.alerts(baseurl=self.target)
        return alerts

    # 4. Filter critical alerts
    def get_critical_alerts(self, alerts):
        return [a for a in alerts if a.get("risk") == "High"]

    # 5. Deep rescan for critical endpoints
    def deep_rescan(self, alerts):
        print("[*] Running deep rescan on critical endpoints...")

        for alert in alerts:
            url = alert.get("url")
            if url:
                print(f"Rescanning: {url}")
                self.zap.ascan.scan(url)

    # 6. Full pipeline
    def run_full_scan(self):
        print(f"[*] Target: {self.target}")

        # spider
        self.spider()

        # active scan
        self.active_scan()

        # alerts
        alerts = self.get_alerts()

        critical = self.get_critical_alerts(alerts)

        if critical:
            self.deep_rescan(critical)

        return {
            "total_alerts": len(alerts),
            "critical_alerts": len(critical),
            "alerts": alerts,
        }


if __name__ == "__main__":
    target_url = "http://demo.testfire.net"

    scanner = ZAPScanManager(
        target=target_url,
        api_key="YOUR_API_KEY"
    )

    results = scanner.run_full_scan()

    with open(r"d:\vulnera\zap_report.json", "w") as f:
        json.dump(results, f, indent=4)

    print("[+] Report saved to zap_report.json")