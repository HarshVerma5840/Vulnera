from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from datetime import datetime

Base = declarative_base()

class NmapScan(Base):
    __tablename__ = "nmap_scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)  # e.g., "scan_abc123xyz789"
    target_url = Column(String, index=True)
    app_type = Column(String)  # e.g., "ecommerce", "blog"
    scan_speed = Column(String, default="standard")  # standard, fast, thorough
    extended_ports = Column(Integer, default=0)  # 0 or 1
    max_timeout = Column(Integer, default=300)
    status = Column(String, default="queued")  # queued, running, complete, failed
    progress = Column(Integer, default=0)  # 0-100
    current_stage = Column(String)  # e.g., "Running NMAP scan"
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    findings = Column(JSON, nullable=True)  # Store findings as JSON
    overall_score = Column(Integer, default=0)  # 0-100

class NmapFinding(Base):
    __tablename__ = "nmap_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, index=True)
    finding_id = Column(String, unique=True, index=True)
    port = Column(Integer)
    service = Column(String)
    product = Column(String)
    version = Column(String)
    severity = Column(String)  # CRITICAL, HIGH, MEDIUM, LOW
    cve_ids = Column(JSON, nullable=True)
    evidence = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class NmapFeedback(Base):
    __tablename__ = "nmap_feedback"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, index=True)
    finding_id = Column(String, index=True)
    verdict = Column(String)  # true_positive, false_positive, unsure
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Keep existing ZAP models
class ZapHistory(Base):
    __tablename__ = "zaphistory"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    result = Column(Text)
    status = Column(String)

