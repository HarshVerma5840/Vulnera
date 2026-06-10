import requests
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
    def __init__(self, target, api_key="", zap_host="127.0.0.1", zap_port="8080", nmap_fingerprint=""):
        self.target = target
        self.nmap_fingerprint = nmap_fingerprint.lower()

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


    def _configure_spider(self, mode="full"):
        """Tunes the spider to prevent infinite crawling on large applications."""
        print(f"[*] Configuring Spider settings for '{mode}' mode...")
        try:
            # Quick mode gets a shallow crawl, Full mode gets standard depth
            depth = 3 if mode == "quick" else 5
            self.zap.spider.set_option_max_depth(depth)
            self.zap.spider.set_option_max_children(20)
            self.zap.spider.set_option_thread_count(7)
            print(f"[+] Spider tuned: max_depth={depth}, max_children=20, threads=7")
        except Exception as e:
            print(f"[-] Failed to configure spider: {e}")

    
    def _apply_quick_scan_plugins(self):
        """Disables all but the most critical active scan plugins for speed."""
        print("[*] Applying Quick Scan policy (High-Value plugins only)...")
        # Top critical plugins (SQLi, XSS, CMDi, Path Traversal, XXE, etc.)
        HIGH_VALUE_PLUGINS = "40012,40018,90020,90019,40014,40016,40017,90021,90023,90024"
        
        try:
            # Disable everything first, then selectively enable the heavy hitters
            self.zap.ascan.disable_all_scanners(scanpolicyname=SCAN_POLICY_NAME)
            self.zap.ascan.enable_scanners(ids=HIGH_VALUE_PLUGINS, scanpolicyname=SCAN_POLICY_NAME)
            print("[+] Quick scan policy applied: Only core injection attacks enabled.")
        except Exception as e:
            print(f"[-] Failed to configure quick scan policy: {e}")

    def _deduplicate_alerts(self, alerts):
        """Groups duplicate alerts to shrink the report size and improve readability."""
        print("[*] Deduplicating alerts for report generation...")
        grouped = {}
        
        for alert in alerts:
            # Use pluginId, name, and risk to form a unique grouping key
            key = (alert.get("pluginId", ""), alert.get("name", ""), alert.get("risk", ""))
            
            if key not in grouped:
                grouped[key] = {
                    "name": alert.get("name"),
                    "risk": alert.get("risk"),
                    "pluginId": alert.get("pluginId"),
                    "description": alert.get("description"),
                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),
                    "tags": alert.get("tags"),
                    "occurrence_count": 0,
                    "affected_urls": []
                }
            
            # Increment count and add unique URLs
            grouped[key]["occurrence_count"] += 1
            url = alert.get("url")
            if url and url not in grouped[key]["affected_urls"]:
                grouped[key]["affected_urls"].append(url)
        
        print(f"[+] Compressed {len(alerts)} raw alerts into {len(grouped)} grouped alerts")
        return list(grouped.values())

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

    def _detect_and_exclude_technologies(self):
        """Infers the tech stack from HTTP headers to skip irrelevant active scan attacks."""
        print("[*] Detecting target technology stack...")
        try:
            # Fetch a sample response to inspect headers
            response = requests.get(self.target, timeout=10, verify=False)
            server_header = response.headers.get("Server", "").lower()
            x_powered = response.headers.get("X-Powered-By", "").lower()
            
            headers_combined = f"{server_header} {x_powered} {self.nmap_fingerprint}"
            print(f"    Headers found: Server='{server_header}', X-Powered-By='{x_powered}'")
            if self.nmap_fingerprint:
                print(f"    Nmap Fingerprint provided: '{self.nmap_fingerprint}'")

            # ZAP's internal technology node names
            exclude_tech = []

            # Heuristics: If we don't see evidence of a tech, we exclude it
            if "php" not in headers_combined:
                exclude_tech.append("Language.PHP")
            
            if "asp" not in headers_combined and "iis" not in headers_combined:
                exclude_tech.append("Language.ASP")
                
            if "java" not in headers_combined and "tomcat" not in headers_combined and "coyote" not in headers_combined and "jsp" not in headers_combined:
                exclude_tech.extend(["Language.JSP/Servlet", "Language.Java"])
                
            if "python" not in headers_combined and "wsgi" not in headers_combined:
                exclude_tech.append("Language.Python")

            if exclude_tech:
                print(f"[*] Excluding irrelevant technologies: {', '.join(exclude_tech)}")
                # Apply exclusions to the Default Context
                self.zap.context.exclude_context_technologies(
                    contextname="Default Context", 
                    technologynames=",".join(exclude_tech)
                )
                print("[+] Technologies excluded successfully")
            else:
                print("[*] Could not reliably narrow down tech stack. Scanning all technologies.")

        except Exception as e:
            print(f"[-] Technology detection failed (ignoring and proceeding): {e}")

    # 6. Full pipeline
    def run_full_scan(self, mode="full"):
        print(f"[*] Target: {self.target} | Mode: {mode.upper()}")
        start_time = datetime.now()

        # Configure baseline rules
        self._configure_exclusions()
        self._configure_scan_policy()
        
        # Apply Quick Mode constraints if requested
        if mode == "quick":
            self._apply_quick_scan_plugins()

        self._configure_spider(mode=mode)

        # 1. Spider
        self.spider()

        # 2. Tech Exclusions (Chunk 5)
        self._detect_and_exclude_technologies()

        # 3. Active Scan
        self.active_scan()

        # 4. Alerts & Deep Rescan
        alerts = self.get_alerts()
        critical = self.get_critical_alerts(alerts)

        # Only run deep rescan in full mode
        if critical and mode == "full":
            self.deep_rescan(critical)
            alerts = self.get_alerts()
            critical = self.get_critical_alerts(alerts)
        elif critical and mode == "quick":
            print("[*] Skipping Deep Rescan (Quick Mode active)")

        end_time = datetime.now()
        duration_seconds = int((end_time - start_time).total_seconds())

        grouped_alerts = self._deduplicate_alerts(alerts)

        return {
            "scan_mode": mode,
            "scan_start_time": start_time.isoformat(),
            "scan_end_time": end_time.isoformat(),
            "scan_duration_seconds": duration_seconds,
            "total_raw_alerts": len(alerts),
            "total_grouped_alerts": len(grouped_alerts),
            "critical_raw_alerts": len(critical),
            "grouped_alerts": grouped_alerts,
            "raw_alerts": alerts, 
        }
