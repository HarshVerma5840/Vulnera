from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session
from datetime import datetime
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import threading
import uuid
import json
import os
from supabase import create_client, Client

from feedback_loop import FeedbackEngine
from pydantic import BaseModel
from typing import List

from database import session
from database_models import VulneraScan, CapturedEndpoint, Alert

# Intelligence layer imports (Phase 0-3)
from normaliser import normalise_all
from endpoint_scorer import EndpointScorer
from risk_scorer import RiskScorer
from cwe_lookup import CWELookup

# Initialise intelligence components
endpoint_scorer = EndpointScorer()
risk_scorer = RiskScorer()
cwe_lookup = CWELookup()
feedback_engine = FeedbackEngine()

# Report generator
from report_generator import ReportGenerator
report_generator = ReportGenerator()

app = FastAPI(title="Vulnera", version="1.0.0")
class EndpointItem(BaseModel):
    path: str
    method: str

class EndpointRequest(BaseModel):
    scan_id: str
    app_type: str
    endpoints: List[EndpointItem]

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def greet():
    return {"message": "Welcome to Vulnera", "version": "1.0.0"}

# ============================================================================
# ENDPOINT INGESTION API
# ============================================================================

@app.post("/api/endpoints")
def receive_endpoints(
    request: EndpointRequest,
    db: Session = Depends(get_db)
):

    for endpoint in request.endpoints:

        db.add(
            CapturedEndpoint(
                scan_id=request.scan_id,
                path=endpoint.path,
                method=endpoint.method
            )
        )

    db.commit()

    return {
        "success": True,
        "stored": len(request.endpoints)
    }


# ============================================================================
# UNIFIED VULNERASCAN ENDPOINTS (Nmap + ZAP)
# ============================================================================

# We still keep in-memory status for real-time fast polling, but we persist to Supabase
vulnerascan_status = {}

@app.post("/api/vulnerascan", response_model=dict)
def start_vulnerascan(
    target: str = "demo.testfire.net",
    zap_mode: str = "quick",
    app_type: str = None,
    db: Session = Depends(get_db)
):
    """
    Start a unified vulnerability scan.
    1. Runs Nmap to discover open ports and services.
    2. Identifies all HTTP/HTTPS web applications.
    3. Runs ZAP on every discovered web application sequentially.
    """
    scan_id = f"vulnscan_{uuid.uuid4().hex[:16]}"
    
    # Initialize in-memory state
    vulnerascan_status[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "zap_mode": zap_mode,
        "app_type": app_type,
        "status": "starting",
        "current_action": "Initializing",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "error": None,
        "results": {
            "timing": {
                "total_duration_seconds": 0,
                "nmap_duration_seconds": 0,
                "zap_duration_seconds": 0
            },
            "nmap_results": None,
            "discovered_web_targets": [],
            "zap_reports": []
        }
    }
    
    # Persist to Supabase Postgres
    db_scan = VulneraScan(
        scan_id=scan_id,
        target=target,
        zap_mode=zap_mode,
        status="starting",
        current_action="Initializing"
    )
    db.add(db_scan)
    db.commit()
    
    def run_unified_scan():
        db_bg = session()
        try:
            import time
            from nmap import scan_host
            from zap.scanner import ZAPScanManager
            from zap.config import ZAP_API_KEY, ZAP_HOST, ZAP_PORT
            
            scan_start_time = time.time()
            
            # Step 1: Nmap
            vulnerascan_status[scan_id]["status"] = "nmap_scanning"
            vulnerascan_status[scan_id]["current_action"] = f"Running Nmap scan on {target}..."
            
            # Update DB state
            db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                "status": "nmap_scanning",
                "current_action": f"Running Nmap scan on {target}..."
            })
            db_bg.commit()
            
            nmap_start = time.time()
            nmap_data = scan_host(target)
            nmap_duration = time.time() - nmap_start
            vulnerascan_status[scan_id]["results"]["timing"]["nmap_duration_seconds"] = round(nmap_duration, 2)
            vulnerascan_status[scan_id]["results"]["nmap_results"] = nmap_data
            
            # Step 2: Parse HTTP/HTTPS ports
            web_targets = []
            
            for host_info in nmap_data:
                for port_info in host_info.get("ports", []):
                    port = port_info.get("port")
                    state = port_info.get("state")
                    service = port_info.get("service", "").lower()
                    
                    if state == "open" and ("http" in service or "ssl" in service or "www" in service):
                        protocol = "https" if ("ssl" in service or port == 443) else "http"
                        base_target = target.replace("http://", "").replace("https://", "").split("/")[0]
                        
                        if port in (80, 443):
                            url = f"{protocol}://{base_target}"
                        else:
                            url = f"{protocol}://{base_target}:{port}"
                            
                        # Extract fingerprint info from Nmap
                        product = port_info.get("product", "").lower()
                        version = port_info.get("version", "").lower()
                        fingerprint = f"{service} {product} {version}".strip()
                        
                        web_targets.append((url, fingerprint))
            
            # Deduplicate targets while preserving fingerprints
            unique_targets = {}
            for url, fp in web_targets:
                if url not in unique_targets:
                    unique_targets[url] = fp
                else:
                    unique_targets[url] += " " + fp
            
            web_targets_list = list(unique_targets.items())
            
            vulnerascan_status[scan_id]["results"]["discovered_web_targets"] = [url for url, fp in web_targets_list]
            
            # Step 3: ZAP Scans
            vulnerascan_status[scan_id]["status"] = "zap_scanning"
            zap_start = time.time()
            
            db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                "status": "zap_scanning",
                "current_action": "Starting ZAP vulnerability scans..."
            })
            db_bg.commit()
            
            if not web_targets_list:
                # Fallback if Nmap couldn't identify service accurately
                print("[!] Nmap didn't explicitly identify HTTP services, falling back to original target.")
                protocol = "https" if target.startswith("https") else "http"
                base_target = target.replace("http://", "").replace("https://", "").split("/")[0]
                web_targets_list = [(f"{protocol}://{base_target}", "")]
            
            for index, (web_target, fingerprint) in enumerate(web_targets_list):
                action_text = f"Running ZAP scan ({zap_mode} mode) on {web_target} ({index+1}/{len(web_targets_list)})..."
                vulnerascan_status[scan_id]["current_action"] = action_text
                
                db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                    "current_action": action_text
                })
                db_bg.commit()
                
                scanner = ZAPScanManager(
                    target=web_target,
                    api_key=ZAP_API_KEY,
                    zap_host=ZAP_HOST,
                    zap_port=ZAP_PORT,
                    nmap_fingerprint=fingerprint
                )
                try:
                    zap_results = scanner.run_full_scan(mode=zap_mode)
                    vulnerascan_status[scan_id]["results"]["zap_reports"].append({
                        "target": web_target,
                        "success": True,
                        "data": zap_results
                    })
                except Exception as ze:
                    vulnerascan_status[scan_id]["results"]["zap_reports"].append({
                        "target": web_target,
                        "success": False,
                        "error": str(ze)
                    })
            
            zap_duration = time.time() - zap_start
            vulnerascan_status[scan_id]["results"]["timing"]["zap_duration_seconds"] = round(zap_duration, 2)
            
            # ============================================================
            # INTELLIGENCE LAYER — Normalise, Score, Enrich
            # ============================================================
            
            vulnerascan_status[scan_id]["status"] = "enriching"
            vulnerascan_status[scan_id]["current_action"] = "Running AI intelligence analysis..."
            
            db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                "status": "enriching",
                "current_action": "Running AI intelligence analysis..."
            })
            db_bg.commit()
            
            # Collect all raw alerts from all ZAP reports
            all_raw_zap_alerts = []
            for zap_report in vulnerascan_status[scan_id]["results"]["zap_reports"]:
                if zap_report.get("success") and zap_report.get("data"):
                    all_raw_zap_alerts.extend(
                        zap_report["data"].get("raw_alerts", [])
                    )
            
            # Step 1: Normalise
            print("[*] Step 1/5: Normalising alerts...")
            nmap_data = vulnerascan_status[scan_id]["results"]["nmap_results"] or []
            unified_alerts = normalise_all(all_raw_zap_alerts, nmap_data)
            print(f"[+] Normalised {len(unified_alerts)} alerts")
            
            # Step 2: Endpoint scoring
            print("[*] Step 2/5: Scoring endpoint sensitivity...")
            endpoint_scores = {}
            for alert in unified_alerts:
                result = endpoint_scorer.score_endpoint(
                    alert.get("path", "/"),
                    app_type=app_type
                )
                endpoint_scores[alert["alert_id"]] = result["score"]
                
            # Step 3: Cross-tool amplification
            print("[*] Step 3/5: Computing cross-tool amplification...")
            amplifications = risk_scorer.compute_all_amplifications(
                unified_alerts, nmap_data
            )
            
            # Step 4: Risk scoring (CVSS + EPSS + composite)
            print("[*] Step 4/5: Computing risk scores (calling NVD/EPSS APIs)...")
            vulnerascan_status[scan_id]["current_action"] = "Fetching CVSS/EPSS data from NVD and FIRST.org..."
            scored_alerts = risk_scorer.score_all(
                unified_alerts, endpoint_scores, amplifications
            )
            
            # Step 5: CWE plain-English enrichment
            print("[*] Step 5/5: Adding plain-English explanations...")
            for alert in scored_alerts:
                cwe_id = alert.get("cwe_id")
                if cwe_id:
                    cwe_info = cwe_lookup.get_plain_english(cwe_id)
                    alert["plain_english"] = cwe_info
                else:
                    alert["plain_english"] = cwe_lookup.get_plain_english(None)
                    
            # Attach to final report
            vulnerascan_status[scan_id]["results"]["alerts"] = scored_alerts
            
            # Save each alert to the alerts table in the database
            for alert_data in scored_alerts:
                tp_prob = feedback_engine.predict_tp_probability(alert_data)
                alert_data["tp_probability"] = tp_prob

                db_alert = Alert(
                    alert_id=alert_data.get("alert_id"),
                    scan_id=scan_id,
                    source=alert_data.get("source"),
                    url=alert_data.get("url"),
                    path=alert_data.get("path"),
                    method=alert_data.get("method"),
                    host=alert_data.get("host"),
                    type=alert_data.get("type"),
                    confidence=alert_data.get("confidence"),
                    original_risk=alert_data.get("risk"),
                    cve_id=alert_data.get("cve_id"),
                    cwe_id=alert_data.get("cwe_id"),
                    risk_score=alert_data.get("risk_score"),
                    risk_level=alert_data.get("risk_level"),
                    endpoint_score=alert_data.get("components", {}).get("endpoint_criticality"),
                    cvss=alert_data.get("components", {}).get("cvss"),
                    epss=alert_data.get("components", {}).get("epss"),
                    amplification_factor=alert_data.get("components", {}).get("amplification", 1.0),
                    plain_english_title=alert_data.get("plain_english", {}).get("title"),
                    plain_english_description=alert_data.get("plain_english", {}).get("what"),
                    plain_english_impact=alert_data.get("plain_english", {}).get("impact"),
                    plain_english_fix=alert_data.get("plain_english", {}).get("fix"),
                    evidence=alert_data.get("evidence"),
                    description=alert_data.get("description"),
                    solution=alert_data.get("solution"),
                    tp_probability=alert_data.get("tp_probability"),
                    raw_data=alert_data.get("raw")
                )
                db_bg.add(db_alert)
            db_bg.commit()

            total_duration = time.time() - scan_start_time
            total_duration_rounded = round(total_duration, 2)
            vulnerascan_status[scan_id]["results"]["timing"]["total_duration_seconds"] = total_duration_rounded
            
            # Save combined report locally as backup
            os.makedirs("zap", exist_ok=True)
            report_path = os.path.join("zap", f"{scan_id}_combined_report.json")
            with open(report_path, "w") as f:
                json.dump(vulnerascan_status[scan_id]["results"], f, indent=4)
            
            # -----------------------------------------------------------------
            # Upload Report to Supabase Storage Bucket
            # -----------------------------------------------------------------
            db_report_path = None
            try:
                bucket_path = f"scans/{scan_id}_combined_report.json"
                vulnerascan_status[scan_id]["current_action"] = "Uploading report to secure cloud storage..."
                db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                    "current_action": "Uploading report to secure cloud storage..."
                })
                db_bg.commit()
                
                with open(report_path, "rb") as f:
                    supabase.storage.from_("reports").upload(
                        path=bucket_path,
                        file=f,
                        file_options={"content-type": "application/json"}
                    )
                db_report_path = bucket_path
                print(f"[+] Successfully uploaded report to Supabase bucket: {db_report_path}")
            except Exception as e:
                print(f"[-] Failed to upload report to Supabase bucket: {e}")
            
            vulnerascan_status[scan_id]["status"] = "complete"
            vulnerascan_status[scan_id]["current_action"] = "Scan finished successfully."
            completion_time = datetime.utcnow()
            vulnerascan_status[scan_id]["completed_at"] = completion_time.isoformat()
            vulnerascan_status[scan_id]["results"]["report_file"] = report_path
            
            # Persist Final Results to Supabase Postgres!
            db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                "status": "complete",
                "current_action": "Scan finished successfully.",
                "completed_at": completion_time,
                "total_duration_seconds": total_duration_rounded,
                "report_path": db_report_path
            })
            db_bg.commit()
            
        except Exception as e:
            vulnerascan_status[scan_id]["status"] = "failed"
            vulnerascan_status[scan_id]["current_action"] = "Scan failed due to an error."
            vulnerascan_status[scan_id]["error"] = str(e)
            
            db_bg.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).update({
                "status": "failed",
                "current_action": "Scan failed due to an error.",
                "error": str(e)
            })
            db_bg.commit()
        finally:
            db_bg.close()
    
    thread = threading.Thread(target=run_unified_scan, daemon=True)
    thread.start()
    
    return {
        "scan_id": scan_id,
        "status": "starting",
        "message": "Unified Nmap+ZAP scan started in background. Use GET /api/vulnerascan/{scan_id} to check progress.",
        "target": target,
        "zap_mode": zap_mode
    }

@app.get("/api/vulnerascan/{scan_id}", response_model=dict)
def get_vulnerascan_status(scan_id: str, db: Session = Depends(get_db)):
    """
    Check the status and current action of a running unified scan.
    """
    db_scan = db.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Unified scan not found")
    
    # We return the live in-memory status if it exists because it updates much faster,
    # otherwise we fall back to the Supabase database (e.g. if the server restarted)
    if scan_id in vulnerascan_status:
        status_data = vulnerascan_status[scan_id].copy()
        if status_data["status"] != "complete":
            status_data.pop("results", None)
        return status_data
    
    return {
        "scan_id": db_scan.scan_id,
        "target": db_scan.target,
        "zap_mode": db_scan.zap_mode,
        "status": db_scan.status,
        "current_action": db_scan.current_action,
        "error": db_scan.error,
        "started_at": db_scan.started_at.isoformat() if db_scan.started_at else None,
        "completed_at": db_scan.completed_at.isoformat() if db_scan.completed_at else None
    }

@app.get("/api/vulnerascan/{scan_id}/results")
def get_vulnerascan_results(scan_id: str, db: Session = Depends(get_db)):
    """
    Get full aggregated results of a completed unified scan from Supabase Bucket.
    """
    db_scan = db.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Unified scan not found")
    
    if db_scan.status != "complete":
        raise HTTPException(status_code=400, detail=f"Scan is not complete. Current status: {db_scan.status}")
    
    # 1. Fetch securely from Supabase Bucket
    if db_scan.report_path:
        try:
            print(f"[*] Downloading report securely from Supabase bucket: {db_scan.report_path}")
            response = supabase.storage.from_("reports").download(db_scan.report_path)
            # The response is binary bytes containing the JSON
            report_data = json.loads(response)
            return JSONResponse(content=report_data)
        except Exception as e:
            print(f"[-] Failed to fetch report from Supabase: {e}")
            
    # 2. Fallback to Local Backup if bucket fails or path is missing
    local_path = os.path.join("zap", f"{scan_id}_combined_report.json")
    if os.path.exists(local_path):
        print(f"[*] Serving fallback local report: {local_path}")
        with open(local_path, "r") as f:
            report_data = json.load(f)
        return JSONResponse(content=report_data)
        
    raise HTTPException(status_code=404, detail="Report file not found in Supabase bucket or local backup.")

@app.get("/api/vulnerascan/{scan_id}/report")
def get_vulnerascan_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Generate and download a branded PDF security report for a completed scan.
    """
    db_scan = db.query(VulneraScan).filter(VulneraScan.scan_id == scan_id).first()

    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if db_scan.status != "complete":
        raise HTTPException(status_code=400, detail=f"Scan is not complete. Current status: {db_scan.status}")

    # Check if we have in-memory data with alerts
    scan_data = None
    if scan_id in vulnerascan_status:
        scan_data = vulnerascan_status[scan_id]

    # Fallback: load from local JSON report
    if not scan_data or "alerts" not in scan_data.get("results", {}):
        local_path = os.path.join("zap", f"{scan_id}_combined_report.json")
        if os.path.exists(local_path):
            with open(local_path, "r") as f:
                results = json.load(f)
            scan_data = {
                "scan_id": scan_id,
                "target": db_scan.target,
                "app_type": getattr(db_scan, "app_type", None),
                "results": results,
            }
        else:
            raise HTTPException(status_code=404, detail="Scan data not found. Cannot generate report.")

    # Generate PDF
    os.makedirs("reports", exist_ok=True)
    pdf_path = os.path.join("reports", f"{scan_id}_report.pdf")
    report_generator.generate_report(scan_data, output_path=pdf_path)

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"vulnera_{scan_id}_report.pdf"
    )
