"""
server.py — Frontend wrapper for Vulnera
=========================================
Imports the EXISTING FastAPI app from main.py and layers on:
  • CORS middleware
  • Static file serving for the frontend SPA
  • JWT auth endpoints (register, login, me)
  • Scan history endpoint

main.py is NOT imported or modified in any way that affects scan logic.
Run with:  uvicorn server:app --reload
"""

from fastapi import HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import hashlib
import secrets
import os
import jwt

# ── Import the EXISTING app & helpers from main.py ─────────────
from main import app, get_db, vulnerascan_status
from database import session
from database_models import VulneraScan, User, Alert, Feedback, ModelCheckpoint

# Phase 4 Imports
from feedback_loop import FeedbackEngine
from agent_reviewer import AgentReviewer
feedback_engine = FeedbackEngine()
agent_reviewer = AgentReviewer()

# ── CORS (allow frontend to call API) ──────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static file serving (Vite build output) ───────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.join(BASE_DIR, "frontend", "dist")

# Only mount if dist exists (i.e., production build has been done)
if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

# ── Serve SPA — catch-all for React Router ────────────────────
@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
@app.get("/signup", response_class=HTMLResponse, include_in_schema=False)
@app.get("/scan", response_class=HTMLResponse, include_in_schema=False)
@app.get("/history", response_class=HTMLResponse, include_in_schema=False)
@app.get("/report/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def serve_frontend_spa(scan_id: str = None):
    index_path = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse(content="<h1>Frontend not built. Run 'npm run build' in frontend/</h1>", status_code=404)

# ── JWT Auth Config ────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7


# ============================================================================
# AUTH HELPERS (pure Python stdlib — no new dependencies)
# ============================================================================

def _hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hashed.hex(), salt

def _create_token(user_id: int, email: str):
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _verify_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing auth token")
    return _verify_token(auth_header[7:])


# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

@app.post("/api/auth/register")
def register(request_body: dict = None, db: Session = Depends(get_db)):
    if not request_body or "email" not in request_body or "password" not in request_body:
        raise HTTPException(status_code=400, detail="Email and password are required")
    email = request_body["email"].strip().lower()
    password = request_body["password"]
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    pw_hash, salt = _hash_password(password)
    user = User(email=email, password_hash=pw_hash, salt=salt)
    db.add(user)
    db.commit()
    db.refresh(user)
    token = _create_token(user.id, user.email)
    return {"token": token, "email": user.email, "user_id": user.id}

@app.post("/api/auth/login")
def login(request_body: dict = None, db: Session = Depends(get_db)):
    if not request_body or "email" not in request_body or "password" not in request_body:
        raise HTTPException(status_code=400, detail="Email and password are required")
    email = request_body["email"].strip().lower()
    password = request_body["password"]
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    pw_hash, _ = _hash_password(password, user.salt)
    if pw_hash != user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = _create_token(user.id, user.email)
    return {"token": token, "email": user.email, "user_id": user.id}

@app.get("/api/auth/me")
def get_me(user=Depends(get_current_user)):
    return {"email": user["email"], "user_id": user["user_id"]}


# ============================================================================
# SCAN HISTORY ENDPOINT
# ============================================================================

@app.get("/api/scan-history")
def get_scan_history(db: Session = Depends(get_db)):
    """Return all past scans ordered by most recent first."""
    scans = db.query(VulneraScan).order_by(VulneraScan.started_at.desc()).all()
    return [
        {
            "scan_id": s.scan_id,
            "target": s.target,
            "zap_mode": s.zap_mode,
            "status": s.status,
            "current_action": s.current_action,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "total_duration_seconds": s.total_duration_seconds,
            "error": s.error,
        }
        for s in scans
    ]


# ============================================================================
# PHASE 4: AGENTIC FEEDBACK LOOP ENDPOINTS
# ============================================================================

@app.get("/api/alerts/{scan_id}")
def get_scan_alerts(scan_id: str, db: Session = Depends(get_db)):
    """Get persisted alerts for a given scan."""
    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).all()
    # Return dicts matching the frontend expectations
    return [
        {
            "alert_id": a.alert_id,
            "scan_id": a.scan_id,
            "source": a.source,
            "type": a.type,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "cwe_id": a.cwe_id,
            "path": a.path,
            "confidence": a.confidence,
            "evidence": a.evidence,
            "plain_english": {
                "title": a.plain_english_title,
                "what": a.plain_english_description,
                "impact": a.plain_english_impact,
                "fix": a.plain_english_fix,
            },
            "feedback_verdict": a.feedback_verdict,
            "feedback_flag": a.feedback_flag,
            "tp_probability": a.tp_probability,
            "raw": a.raw_data
        } for a in alerts
    ]

@app.post("/api/feedback")
def submit_feedback(request_body: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Submit a TP/FP verdict for an alert."""
    alert_id = request_body.get("alert_id")
    verdict = request_body.get("verdict")
    notes = request_body.get("notes", "")
    app_type = request_body.get("app_type", "Unknown")
    
    if not alert_id or verdict not in ["TP", "FP"]:
        raise HTTPException(status_code=400, detail="Invalid request")

    # If the agent previously suggested a verdict, handle overrides
    agent_verdict = request_body.get("agent_verdict")
    if agent_verdict:
        agent_reviewer.handle_override(
            db=db,
            alert_id=alert_id,
            user_id=user["user_id"],
            agent_verdict=agent_verdict,
            human_verdict=verdict,
            human_notes=notes,
            app_type=app_type
        )
        
    try:
        result = feedback_engine.record_feedback(db, alert_id, verdict, user["user_id"], notes)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/api/feedback/stats")
def get_feedback_stats(user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Get user's feedback stats and model status."""
    total_fb = db.query(Feedback).count()
    user_fb = db.query(Feedback).filter(Feedback.user_id == user["user_id"]).count()
    
    last_ckpt = db.query(ModelCheckpoint).order_by(ModelCheckpoint.round.desc()).first()
    model_status = {
        "is_trained": feedback_engine.model is not None,
        "total_feedback_events": total_fb,
        "next_retrain_in": feedback_engine.RETRAIN_THRESHOLD - (total_fb % feedback_engine.RETRAIN_THRESHOLD),
        "latest_f1": last_ckpt.f1_accuracy if last_ckpt else None
    }
    
    return {
        "user_feedback_count": user_fb,
        "model_status": model_status
    }

@app.get("/api/feedback/learning-curve")
def get_learning_curve(db: Session = Depends(get_db)):
    """Get model checkpoint history for chart plotting."""
    return feedback_engine.generate_learning_curve(db)

@app.post("/api/agent/review/{scan_id}")
def batch_agent_review(scan_id: str, request_body: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Trigger the Gemini agent to review all un-reviewed alerts in a scan."""
    app_type = request_body.get("app_type", "Unknown")
    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).all()
    
    # Format for agent_reviewer
    alert_dicts = [{"alert_id": a.alert_id, "type": a.type, "cwe_id": a.cwe_id, 
                   "path": a.path, "original_risk": a.original_risk, "risk_score": a.risk_score,
                   "endpoint_score": a.endpoint_score, "evidence": a.evidence, "description": a.description} 
                   for a in alerts if not a.feedback_verdict]
                   
    results = agent_reviewer.review_batch(db, alert_dicts, user["user_id"], app_type)
    return results

@app.post("/api/agent/review-single")
def single_agent_review(request_body: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Trigger the Gemini agent to review a single alert."""
    alert_id = request_body.get("alert_id")
    app_type = request_body.get("app_type", "Unknown")
    
    db_alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not db_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    alert_dict = {
        "alert_id": db_alert.alert_id, "type": db_alert.type, "cwe_id": db_alert.cwe_id, 
        "path": db_alert.path, "original_risk": db_alert.original_risk, "risk_score": db_alert.risk_score,
        "endpoint_score": db_alert.endpoint_score, "evidence": db_alert.evidence, "description": db_alert.description
    }
    
    result = agent_reviewer.review_alert(db, alert_dict, user["user_id"], app_type)
    return result

@app.get("/api/agent/stats")
def get_agent_stats(user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Get agent accuracy and memory size."""
    patterns = agent_reviewer.user_memory.get_user_patterns(db, user["user_id"])
    return {
        "user_patterns": patterns
    }
