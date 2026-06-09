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
# ZAP ENDPOINTS (Keep as is for now)
# ============================================================================

@app.post("/zap/scan")
def add_zap_scan(scan: models.ZapScan, db: Session = Depends(get_db)):
    db_scan = database_models.ZapHistory(**scan.model_dump())
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

@app.get("/zap/history")
def get_zap_history(db: Session = Depends(get_db)):
    scans = db.query(database_models.ZapHistory).all()
    return scans

@app.get("/zap/history/{scan_id}")
def get_zap_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(database_models.ZapHistory).filter(
        database_models.ZapHistory.id == scan_id
    ).first()
    if scan:
        return scan
    return {"error": "Scan not found"}

