import time
from zapv2 import ZAPv2
from requests.exceptions import RequestException

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
        
        # Verify connection on initialization
        try:
            print(f"[*] Connecting to ZAP at {zap_host}:{zap_port}...")
            # We call a simple endpoint to ensure ZAP is responsive
            self.zap.core.version
        except Exception as e:
            print(f"[-] Failed to connect to ZAP proxy: {e}")
            print(f"[-] Please ensure ZAP is running on {zap_host}:{zap_port}")
            raise SystemExit(1)

    # 1. Spider crawl
    def spider(self):
        print("[*] Starting spider...")
        try:
            scan_id = self.zap.spider.scan(self.target)

            while int(self.zap.spider.status(scan_id)) < 100:
                print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(2)

            print("[+] Spider completed")
        except Exception as e:
            print(f"[-] Spider scan failed: {e}")

    # 2. Active scan (attack simulation)
    def active_scan(self):
        print("[*] Starting active scan...")
        try:
            scan_id = self.zap.ascan.scan(self.target)

            while int(self.zap.ascan.status(scan_id)) < 100:
                print(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
                time.sleep(5)

            print("[+] Active scan completed")
        except Exception as e:
            print(f"[-] Active scan failed: {e}")

    # 3. Get alerts
    def get_alerts(self):
        try:
            alerts = self.zap.core.alerts(baseurl=self.target)
            return alerts
        except Exception as e:
            print(f"[-] Failed to fetch alerts: {e}")
            return []

    # 4. Filter critical alerts
    def get_critical_alerts(self, alerts):
        return [a for a in alerts if a.get("risk") == "High"]

    # 5. Deep rescan for critical endpoints
    def deep_rescan(self, alerts):
        print("[*] Running deep rescan on critical endpoints...")
        
        scan_ids = []
        for alert in alerts:
            url = alert.get("url")
            if url:
                print(f"Rescanning: {url}")
                try:
                    scan_id = self.zap.ascan.scan(url)
                    scan_ids.append((url, scan_id))
                except Exception as e:
                    print(f"[-] Failed to start deep rescan on {url}: {e}")

        # Wait for all deep rescans to finish
        for url, scan_id in scan_ids:
            try:
                while int(self.zap.ascan.status(scan_id)) < 100:
                    print(f"Deep rescan progress for {url}: {self.zap.ascan.status(scan_id)}%")
                    time.sleep(5)
                print(f"[+] Deep rescan completed for {url}")
            except Exception as e:
                print(f"[-] Deep rescan monitoring failed for {url}: {e}")

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
            # Re-fetch alerts after deep rescan to include new findings
            alerts = self.get_alerts()
            critical = self.get_critical_alerts(alerts)

        return {
            "total_alerts": len(alerts),
            "critical_alerts": len(critical),
            "alerts": alerts,
        }
