from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

# NMAP ENDPOINTS - Request/Response Schemas

class StartScanRequest(BaseModel):
    target_url: str
    app_type: str
    scan_speed: Optional[str] = "standard"
    extended_ports: Optional[bool] = False
    max_timeout: Optional[int] = 300

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str  # queued, running, complete, failed
    progress: int  # 0-100
    current_stage: Optional[str]
    started_at: datetime
    estimated_completion: Optional[datetime]
    findings_count: int

class NmapFindingDetail(BaseModel):
    id: Optional[str]
    port: int
    service: str
    product: str
    version: str
    severity: Optional[str] = "LOW"
    cve_ids: Optional[List[str]] = []
    evidence: str

class CompleteScanResponse(BaseModel):
    scan_id: str
    status: str
    progress: int
    target_url: str
    app_type: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    findings: List[NmapFindingDetail]
    overall_score: int

# Vulnera Mode - Simple Response
class CriticalFinding(BaseModel):
    title: str
    description: str
    action: str
    time_to_fix: str

class VulneraModeResponse(BaseModel):
    scan_id: str
    mode: str = "vulnera"
    target: str
    app_type: str
    overall_score: int
    compliance_score: int
    summary: dict
    critical_findings: List[CriticalFinding]
    high_findings: List[dict]
    compliance: dict

# Pro Mode - Detailed Response
class ProModeResponse(BaseModel):
    scan_id: str
    mode: str = "pro"
    target: str
    app_type: str
    findings: List[dict]

class ResultsResponse(BaseModel):
    scan_id: str
    target: str
    app_type: str
    overall_score: int
    findings: List[NmapFindingDetail]

# Feedback
class FeedbackRequest(BaseModel):
    finding_id: str
    verdict: str  # true_positive, false_positive, unsure
    notes: Optional[str] = None

class FeedbackResponse(BaseModel):
    status: str
    finding_id: str
    verdict: str
    message: str
    feedback_count: int
    next_retraining: Optional[str]

# List Scans
class ScanListItem(BaseModel):
    scan_id: str
    target_url: str
    app_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    findings_count: int
    critical_count: int
    score: int

class ListScansResponse(BaseModel):
    total: int
    limit: int
    offset: int
    scans: List[ScanListItem]

# Error Response
class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[dict] = None

# ZAP Endpoints (Keep as is for now)
class NmapScan(BaseModel):
    target: str
    result: str
    status: str

class ZapScan(BaseModel):
    target: str
    result: str
    status: str

