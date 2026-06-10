from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse, FileResponse
import database_models
import models
from database import session
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid
import json
from nmap import scan_host

app = FastAPI(title="Vulnera", version="1.0.0")

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
# NMAP ENDPOINTS
# ============================================================================

@app.get("/api/test-nmap")
def test_nmap():
    results = scan_host("scanme.nmap.org")
    return {
        "status": "success",
        "results": results
    }


# 1. START A NEW SCAN
@app.post("/api/scans", response_model=dict)
def start_nmap_scan(request: models.StartScanRequest, db: Session = Depends(get_db)):
    """
    Start a new NMAP vulnerability scan
    
    Returns:
        - scan_id: Unique identifier for this scan
        - status: "queued"
        - estimated_time: Estimated scan duration in seconds
    """
    try:
        scan_id = f"scan_{uuid.uuid4().hex[:20]}"
        estimated_time = 600 if request.scan_speed == "standard" else (300 if request.scan_speed == "fast" else 1200)
        
        # Create scan record in database
        db_scan = database_models.NmapScan(
            scan_id=scan_id,
            target_url=request.target_url,
            app_type=request.app_type,
            scan_speed=request.scan_speed,
            extended_ports=int(request.extended_ports),
            max_timeout=request.max_timeout,
            status="queued",
            progress=0,
            overall_score=0
        )
        db.add(db_scan)
        db.commit()
        db.refresh(db_scan)
        
        return {
            "status": "queued",
            "scan_id": scan_id,
            "message": "Scan queued successfully",
            "estimated_time": estimated_time,
            "target_url": request.target_url,
            "app_type": request.app_type
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# 2. CHECK SCAN STATUS
@app.get("/api/scans/{scan_id}", response_model=dict)
def check_scan_status(scan_id: str, db: Session = Depends(get_db)):
    """
    Check the status of a running or completed scan
    
    Returns status, progress, and findings count
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    estimated_completion = None
    if db_scan.status == "running" and db_scan.started_at:
        remaining = (100 - db_scan.progress) * 6
        estimated_completion = datetime.utcnow() + timedelta(seconds=remaining)
    
    return {
        "scan_id": db_scan.scan_id,
        "status": db_scan.status,
        "progress": db_scan.progress,
        "current_stage": db_scan.current_stage,
        "started_at": db_scan.started_at,
        "estimated_completion": estimated_completion,
        "findings_count": db_scan.findings_count
    }

# 3. GET SCAN RESULTS (Vulnera Mode - Simple)
@app.get("/api/scans/{scan_id}/results/vulnera", response_model=dict)
def get_scan_results_vulnera(scan_id: str, db: Session = Depends(get_db)):
    """
    Get scan results in Vulnera Mode (Simple, non-technical language)
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if db_scan.status != "complete":
        raise HTTPException(status_code=400, detail="Scan is not complete yet")
    
    findings = json.loads(db_scan.findings) if db_scan.findings else []
    
    critical_findings = [
        {
            "title": f"Port {f.get('port')} ({f.get('service')}) is exposed",
            "description": f"Service {f.get('product')} v{f.get('version')} is running and vulnerable to attacks",
            "action": "Secure this port immediately",
            "time_to_fix": "1-2 days"
        }
        for f in findings if f.get('severity') == 'CRITICAL'
    ]
    
    return {
        "scan_id": db_scan.scan_id,
        "mode": "vulnera",
        "target": db_scan.target_url,
        "app_type": db_scan.app_type,
        "overall_score": db_scan.overall_score,
        "compliance_score": max(0, db_scan.overall_score - 15),
        "summary": {
            "critical_count": db_scan.critical_count,
            "high_count": db_scan.high_count,
            "medium_count": db_scan.medium_count,
            "low_count": db_scan.low_count
        },
        "critical_findings": critical_findings,
        "high_findings": [],
        "compliance": {
            "dpdp_compliant": db_scan.overall_score >= 85,
            "dpdp_score": db_scan.overall_score,
            "dpdp_requirement": 85
        }
    }

# 4. GET SCAN RESULTS (Pro Mode - Detailed)
@app.get("/api/scans/{scan_id}/results/pro", response_model=dict)
def get_scan_results_pro(scan_id: str, db: Session = Depends(get_db)):
    """
    Get scan results in Pro Mode (Detailed, technical language)
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if db_scan.status != "complete":
        raise HTTPException(status_code=400, detail="Scan is not complete yet")
    
    findings = json.loads(db_scan.findings) if db_scan.findings else []
    
    pro_findings = []
    for idx, f in enumerate(findings):
        pro_findings.append({
            "id": f.get('id', f"vuln_{idx:03d}"),
            "type": "service_enumeration",
            "port": f.get('port'),
            "service": f.get('service'),
            "product": f.get('product'),
            "version": f.get('version'),
            "severity": f.get('severity', 'LOW'),
            "score": 50 + (int(f.get('port', 80)) % 50),
            "evidence": f.get('evidence', ''),
            "tool_source": "nmap",
            "tool_confidence": 0.95,
            "remediation": f"Update {f.get('product')} to latest version or disable the service"
        })
    
    return {
        "scan_id": db_scan.scan_id,
        "mode": "pro",
        "target": db_scan.target_url,
        "app_type": db_scan.app_type,
        "started_at": db_scan.started_at,
        "completed_at": db_scan.completed_at,
        "duration_seconds": db_scan.duration_seconds,
        "findings": pro_findings
    }

# 5. SEND FEEDBACK (Mark True/False Positive)
@app.post("/api/scans/{scan_id}/feedback", response_model=dict)
def send_feedback(scan_id: str, request: models.FeedbackRequest, db: Session = Depends(get_db)):
    """
    Send feedback on a finding (true positive, false positive, unsure)
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    feedback = database_models.NmapFeedback(
        scan_id=scan_id,
        finding_id=request.finding_id,
        verdict=request.verdict,
        notes=request.notes
    )
    db.add(feedback)
    db.commit()
    
    feedback_count = db.query(database_models.NmapFeedback).filter(
        database_models.NmapFeedback.scan_id == scan_id
    ).count()
    
    return {
        "status": "recorded",
        "finding_id": request.finding_id,
        "verdict": request.verdict,
        "message": "Feedback recorded. System is learning.",
        "feedback_count": feedback_count,
        "next_retraining": "After 5 more feedback events" if feedback_count % 5 != 0 else "Retraining in progress"
    }

# 6. LIST ALL SCANS
@app.get("/api/scans", response_model=dict)
def list_all_scans(limit: int = 10, offset: int = 0, status: str = None, db: Session = Depends(get_db)):
    """
    List all scans with pagination and optional filtering
    """
    query = db.query(database_models.NmapScan)
    
    if status:
        query = query.filter(database_models.NmapScan.status == status)
    
    total = query.count()
    scans = query.offset(offset).limit(limit).all()
    
    scan_list = [
        {
            "scan_id": scan.scan_id,
            "target_url": scan.target_url,
            "app_type": scan.app_type,
            "status": scan.status,
            "created_at": scan.started_at,
            "completed_at": scan.completed_at,
            "findings_count": scan.findings_count,
            "critical_count": scan.critical_count,
            "score": scan.overall_score
        }
        for scan in scans
    ]
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": scan_list
    }

# 7. DELETE A SCAN
@app.delete("/api/scans/{scan_id}", response_model=dict)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """
    Delete a scan and all its associated data
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.query(database_models.NmapFeedback).filter(
        database_models.NmapFeedback.scan_id == scan_id
    ).delete()
    
    db.delete(db_scan)
    db.commit()
    
    return {
        "status": "deleted",
        "scan_id": scan_id,
        "message": "Scan deleted successfully"
    }

# 8. EXPORT RESULTS (JSON, CSV)
@app.get("/api/scans/{scan_id}/results.json")
def export_results_json(scan_id: str, db: Session = Depends(get_db)):
    """
    Export scan results as JSON
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = json.loads(db_scan.findings) if db_scan.findings else []
    
    return JSONResponse(
        content={
            "scan_id": db_scan.scan_id,
            "target": db_scan.target_url,
            "app_type": db_scan.app_type,
            "status": db_scan.status,
            "overall_score": db_scan.overall_score,
            "findings_count": db_scan.findings_count,
            "findings": findings,
            "metadata": {
                "started_at": db_scan.started_at.isoformat(),
                "completed_at": db_scan.completed_at.isoformat() if db_scan.completed_at else None,
                "duration_seconds": db_scan.duration_seconds
            }
        }
    )

@app.get("/api/scans/{scan_id}/results.csv")
def export_results_csv(scan_id: str, db: Session = Depends(get_db)):
    """
    Export scan results as CSV
    """
    db_scan = db.query(database_models.NmapScan).filter(
        database_models.NmapScan.scan_id == scan_id
    ).first()
    
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = json.loads(db_scan.findings) if db_scan.findings else []
    
    csv_lines = ["port,service,product,version,severity,evidence"]
    for f in findings:
        csv_lines.append(
            f"{f.get('port')},{f.get('service')},{f.get('product')},{f.get('version')},"
            f"{f.get('severity')},\"{f.get('evidence', '')}\""
        )
    
    csv_content = "\n".join(csv_lines)
    
    return JSONResponse(
        content={"csv": csv_content},
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"}
    )

# ============================================================================
# ZAP ENDPOINTS
# ============================================================================

import threading
import os

# In-memory store for background ZAP scan status (will move to DB later)
zap_scan_status = {}

@app.post("/api/zap/scan", response_model=dict)
def start_zap_scan(
    target: str = "http://demo.testfire.net",
    mode: str = "quick"
):
    """
    Start a ZAP vulnerability scan against a target URL.
    
    Requires OWASP ZAP proxy to be running on zap_host:zap_port.
    The scan runs in the background — use GET /api/zap/scan/{scan_id} to check status.
    
    - **mode**: 'quick' (fast, high-value plugins only) or 'full' (comprehensive)
    """
    scan_id = f"zap_{uuid.uuid4().hex[:16]}"
    
    zap_scan_status[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "mode": mode,
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "error": None,
        "results": None
    }
    
    def run_scan():
        try:
            from zap.scanner import ZAPScanManager
            from zap.config import ZAP_API_KEY, ZAP_HOST, ZAP_PORT
            
            zap_scan_status[scan_id]["status"] = "running"
            
            scanner = ZAPScanManager(
                target=target,
                api_key=ZAP_API_KEY,
                zap_host=ZAP_HOST,
                zap_port=ZAP_PORT
            )
            results = scanner.run_full_scan(mode=mode)
            
            # Save report to file
            report_path = os.path.join("zap", f"{scan_id}_report.json")
            with open(report_path, "w") as f:
                json.dump(results, f, indent=4)
            
            zap_scan_status[scan_id]["status"] = "complete"
            zap_scan_status[scan_id]["completed_at"] = datetime.utcnow().isoformat()
            zap_scan_status[scan_id]["results"] = {
                "total_raw_alerts": results.get("total_raw_alerts", 0),
                "total_grouped_alerts": results.get("total_grouped_alerts", 0),
                "critical_raw_alerts": results.get("critical_raw_alerts", 0),
                "scan_duration_seconds": results.get("scan_duration_seconds", 0),
                "report_file": report_path
            }
        except Exception as e:
            zap_scan_status[scan_id]["status"] = "failed"
            zap_scan_status[scan_id]["error"] = str(e)
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return {
        "scan_id": scan_id,
        "status": "starting",
        "message": "ZAP scan started in background. Use GET /api/zap/scan/{scan_id} to check progress.",
        "target": target,
        "mode": mode
    }


@app.get("/api/zap/scan/{scan_id}", response_model=dict)
def get_zap_scan_status(scan_id: str):
    """
    Check the status of a running or completed ZAP scan.
    """
    if scan_id not in zap_scan_status:
        raise HTTPException(status_code=404, detail="ZAP scan not found")
    
    return zap_scan_status[scan_id]


@app.get("/api/zap/scan/{scan_id}/results", response_model=dict)
def get_zap_scan_results(scan_id: str):
    """
    Get full results of a completed ZAP scan.
    """
    if scan_id not in zap_scan_status:
        raise HTTPException(status_code=404, detail="ZAP scan not found")
    
    scan = zap_scan_status[scan_id]
    if scan["status"] != "complete":
        raise HTTPException(status_code=400, detail=f"Scan is not complete. Current status: {scan['status']}")
    
    report_path = scan["results"].get("report_file")
    if report_path and os.path.exists(report_path):
        with open(report_path, "r") as f:
            report = json.load(f)
        return report
    
    raise HTTPException(status_code=404, detail="Report file not found")


@app.get("/api/zap/report/latest", response_model=dict)
def get_latest_zap_report():
    """
    Load the latest saved ZAP report (zap/zap_report.json).
    Useful for testing without running a live scan.
    """
    report_path = os.path.join("zap", "zap_report.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="No ZAP report found. Run a scan first.")
    
    with open(report_path, "r") as f:
        report = json.load(f)
    
    return {
        "source": "cached_report",
        "file": report_path,
        "scan_start_time": report.get("scan_start_time"),
        "scan_end_time": report.get("scan_end_time"),
        "scan_duration_seconds": report.get("scan_duration_seconds"),
        "total_alerts": report.get("total_alerts"),
        "critical_alerts": report.get("critical_alerts"),
        "alert_count": len(report.get("alerts", []))
    }


@app.get("/api/zap/scans", response_model=dict)
def list_zap_scans():
    """
    List all ZAP scans (in-memory for now).
    """
    scans = [
        {
            "scan_id": s["scan_id"],
            "target": s["target"],
            "mode": s["mode"],
            "status": s["status"],
            "started_at": s["started_at"],
            "completed_at": s["completed_at"],
        }
        for s in zap_scan_status.values()
    ]
    return {"total": len(scans), "scans": scans}

# ============================================================================
# UNIFIED VULNERASCAN ENDPOINTS (Nmap + ZAP)
# ============================================================================

vulnerascan_status = {}

@app.post("/api/vulnerascan", response_model=dict)
def start_vulnerascan(
    target: str = "demo.testfire.net",
    zap_mode: str = "quick"
):
    """
    Start a unified vulnerability scan.
    1. Runs Nmap to discover open ports and services.
    2. Identifies all HTTP/HTTPS web applications.
    3. Runs ZAP on every discovered web application sequentially.
    """
    scan_id = f"vulnscan_{uuid.uuid4().hex[:16]}"
    
    vulnerascan_status[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "zap_mode": zap_mode,
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
    
    def run_unified_scan():
        try:
            import time
            from nmap import scan_host
            from zap.scanner import ZAPScanManager
            from zap.config import ZAP_API_KEY, ZAP_HOST, ZAP_PORT
            
            scan_start_time = time.time()
            
            # Step 1: Nmap
            vulnerascan_status[scan_id]["status"] = "nmap_scanning"
            vulnerascan_status[scan_id]["current_action"] = f"Running Nmap scan on {target}..."
            
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
                            
                        web_targets.append(url)
            
            # Deduplicate targets
            web_targets = list(set(web_targets))
            vulnerascan_status[scan_id]["results"]["discovered_web_targets"] = web_targets
            
            # Step 3: ZAP Scans
            vulnerascan_status[scan_id]["status"] = "zap_scanning"
            zap_start = time.time()
            
            if not web_targets:
                # Fallback if Nmap couldn't identify service accurately
                print("[!] Nmap didn't explicitly identify HTTP services, falling back to original target.")
                protocol = "https" if target.startswith("https") else "http"
                base_target = target.replace("http://", "").replace("https://", "").split("/")[0]
                web_targets = [f"{protocol}://{base_target}"]
            
            for index, web_target in enumerate(web_targets):
                vulnerascan_status[scan_id]["current_action"] = f"Running ZAP scan ({zap_mode} mode) on {web_target} ({index+1}/{len(web_targets)})..."
                
                scanner = ZAPScanManager(
                    target=web_target,
                    api_key=ZAP_API_KEY,
                    zap_host=ZAP_HOST,
                    zap_port=ZAP_PORT
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
            
            total_duration = time.time() - scan_start_time
            vulnerascan_status[scan_id]["results"]["timing"]["total_duration_seconds"] = round(total_duration, 2)
            
            # Save combined report
            report_path = os.path.join("zap", f"{scan_id}_combined_report.json")
            with open(report_path, "w") as f:
                json.dump(vulnerascan_status[scan_id]["results"], f, indent=4)
            
            vulnerascan_status[scan_id]["results"]["report_file"] = report_path
            vulnerascan_status[scan_id]["status"] = "complete"
            vulnerascan_status[scan_id]["current_action"] = "Scan finished successfully."
            vulnerascan_status[scan_id]["completed_at"] = datetime.utcnow().isoformat()
            
        except Exception as e:
            vulnerascan_status[scan_id]["status"] = "failed"
            vulnerascan_status[scan_id]["current_action"] = "Scan failed due to an error."
            vulnerascan_status[scan_id]["error"] = str(e)
    
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
def get_vulnerascan_status(scan_id: str):
    """
    Check the status and current action of a running unified scan.
    """
    if scan_id not in vulnerascan_status:
        raise HTTPException(status_code=404, detail="Unified scan not found")
    
    # Return everything except the massive results payload to keep it fast while running
    status_data = vulnerascan_status[scan_id].copy()
    if status_data["status"] != "complete":
        status_data.pop("results", None)
    return status_data

@app.get("/api/vulnerascan/{scan_id}/results", response_model=dict)
def get_vulnerascan_results(scan_id: str):
    """
    Get full aggregated results of a completed unified scan.
    """
    if scan_id not in vulnerascan_status:
        raise HTTPException(status_code=404, detail="Unified scan not found")
    
    scan = vulnerascan_status[scan_id]
    if scan["status"] != "complete":
        raise HTTPException(status_code=400, detail=f"Scan is not complete. Current status: {scan['status']}")
    
    report_path = scan["results"].get("report_file")
    if report_path and os.path.exists(report_path):
        with open(report_path, "r") as f:
            report = json.load(f)
        return report
    
    raise HTTPException(status_code=404, detail="Report file not found")
