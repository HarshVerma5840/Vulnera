import time
from datetime import datetime
from zapv2 import ZAPv2
from requests.exceptions import RequestException

EXCLUSION_REGEXES = [
    # Static Assets (Stylesheets, Fonts, Images, Media, Maps)
    r".*\.css$", r".*\.scss$", r".*\.less$",
    r".*\.woff$", r".*\.woff2$", r".*\.ttf$", r".*\.eot$", r".*\.otf$",
    r".*\.png$", r".*\.jpg$", r".*\.jpeg$", r".*\.gif$", r".*\.svg$", r".*\.ico$", r".*\.webp$", r".*\.bmp$",
    r".*\.mp4$", r".*\.mp3$", r".*\.wav$", r".*\.webm$", r".*\.avi$",
    r".*\.js\.map$", r".*\.css\.map$",
    # Directories (Client-side dependencies)
    r".*/node_modules/.*", r".*/vendor/.*", r".*/bower_components/.*", r".*/\.venv/.*",
    # Third-party Domains
    r".*\.google-analytics\.com.*", r".*\.googletagmanager\.com.*", r".*\.facebook\.net.*", r".*\.hotjar\.com.*", r".*\.stripe\.com.*"
]

# Plugin IDs to disable (noisy, low-value alerts)
DISABLED_PLUGINS = [
    "10104",  # User Agent Fuzzer — Informational, 124 alerts in baseline scan
    "10036",  # Server Leaks Version Info — Low, 116 alerts in baseline scan
]

SCAN_POLICY_NAME = "vulnera_optimized"

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

    def _configure_exclusions(self):
        print("[*] Configuring ZAP scan exclusions...")
        for regex in EXCLUSION_REGEXES:
            try:
                self.zap.spider.exclude_from_scan(regex)
                self.zap.ascan.exclude_from_scan(regex)
            except Exception as e:
                print(f"[-] Failed to apply exclusion regex {regex}: {e}")

    def _configure_scan_policy(self):
        """Create a custom scan policy that disables noisy, low-value plugins."""
        print("[*] Configuring custom scan policy...")
        try:
            # Remove existing policy if it exists, then create fresh
            try:
                self.zap.ascan.remove_scan_policy(SCAN_POLICY_NAME)
            except Exception:
                pass
            self.zap.ascan.add_scan_policy(SCAN_POLICY_NAME)

            for plugin_id in DISABLED_PLUGINS:
                self.zap.ascan.set_scanner_alert_threshold(
                    id=plugin_id, alertthreshold="OFF", scanpolicyname=SCAN_POLICY_NAME
                )
                print(f"    Disabled plugin {plugin_id}")

            print(f"[+] Scan policy '{SCAN_POLICY_NAME}' configured")
        except Exception as e:
            print(f"[-] Failed to configure scan policy: {e}")


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
            scan_id = self.zap.ascan.scan(self.target, scanpolicyname=SCAN_POLICY_NAME)

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
        
        # Deduplicate URLs to avoid rescanning the same endpoint multiple times
        unique_urls = list({alert.get("url") for alert in alerts if alert.get("url")})
        print(f"[*] {len(alerts)} high-risk alerts mapped to {len(unique_urls)} unique URLs")

        scan_ids = []
        for url in unique_urls:
            print(f"Rescanning: {url}")
            try:
                scan_id = self.zap.ascan.scan(url, scanpolicyname=SCAN_POLICY_NAME)
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
        start_time = datetime.now()

        # Configure exclusions and scan policy before starting
        self._configure_exclusions()
        self._configure_scan_policy()

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

        end_time = datetime.now()
        duration_seconds = int((end_time - start_time).total_seconds())

        return {
            "scan_start_time": start_time.isoformat(),
            "scan_end_time": end_time.isoformat(),
            "scan_duration_seconds": duration_seconds,
            "total_alerts": len(alerts),
            "critical_alerts": len(critical),
            "alerts": alerts,
        }
