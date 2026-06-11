from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from datetime import datetime

Base = declarative_base()

class VulneraScan(Base):
    __tablename__ = "vulnera_scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    target = Column(String, index=True)
    zap_mode = Column(String)
    status = Column(String)
    current_action = Column(String)
    error = Column(String, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_duration_seconds = Column(Float, nullable=True)
    report_path = Column(String, nullable=True)
