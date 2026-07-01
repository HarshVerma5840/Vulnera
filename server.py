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
from database_models import VulneraScan, User

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
