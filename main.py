
from fastapi import FastAPI, Depends
import database_models
from models import NmapScan, ZapScan
from database import session
from sqlalchemy.orm import Session

app=FastAPI();

@app.get("/")
def greet():
    return "Welcome to Vulnerability Scanner"

def get_db():
    db=session()
    try:
        yield db
    finally:
        db.close()

# NMAP ENDPOINTS
@app.post("/nmap/scan")
def add_nmap_scan(scan: NmapScan, db: Session=Depends(get_db)):
    db_scan = database_models.NmapHistory(**scan.model_dump())
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

@app.get("/nmap/history")
def get_nmap_history(db: Session=Depends(get_db)):
    scans = db.query(database_models.NmapHistory).all()
    return scans

@app.get("/nmap/history/{scan_id}")
def get_nmap_scan(scan_id: int, db: Session=Depends(get_db)):
    scan = db.query(database_models.NmapHistory).filter(database_models.NmapHistory.id==scan_id).first()
    if scan:
        return scan
    return {"error": "Scan not found"}

# ZAP ENDPOINTS
@app.post("/zap/scan")
def add_zap_scan(scan: ZapScan, db: Session=Depends(get_db)):
    db_scan = database_models.ZapHistory(**scan.model_dump())
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

@app.get("/zap/history")
def get_zap_history(db: Session=Depends(get_db)):
    scans = db.query(database_models.ZapHistory).all()
    return scans

@app.get("/zap/history/{scan_id}")
def get_zap_scan(scan_id: int, db: Session=Depends(get_db)):
    scan = db.query(database_models.ZapHistory).filter(database_models.ZapHistory.id==scan_id).first()
    if scan:
        return scan
    return {"error": "Scan not found"}


