from sqlalchemy.orm import declarative_base  # Fixed: was sqlalchemy.ext.declarative (deprecated)
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Text
from datetime import datetime

Base = declarative_base()


# ============================================================================
# EXISTING TABLES
# ============================================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


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


class CapturedEndpoint(Base):
    __tablename__ = "captured_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, index=True)
    path = Column(String)
    method = Column(String)


# ============================================================================
# PHASE 4 — AGENTIC FEEDBACK LOOP TABLES
# ============================================================================

class Alert(Base):
    """
    Persists every individual enriched finding from a scan.
    One row per alert per scan. Replaces the raw JSON blob approach
    so the feedback system can reference specific alerts.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)   # "zap_40012_abc123"
    scan_id = Column(String, index=True)                  # Links to vulnera_scans
    user_id = Column(Integer, nullable=True, index=True)  # Who initiated the scan

    # Source & location
    source = Column(String)            # "zap" or "nmap"
    url = Column(String)
    path = Column(String)
    method = Column(String)
    host = Column(String)

    # Classification
    type = Column(String)              # "xss_reflected", "sqli", "open_port", etc.
    confidence = Column(String)        # "High", "Medium", "Low"
    original_risk = Column(String)     # Original risk from tool (High/Medium/Low/Info)

    # Enrichment (from Phases 1-3)
    cve_id = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    risk_score = Column(Float, nullable=True)        # Composite score (0-1)
    risk_level = Column(String, nullable=True)       # CRITICAL/HIGH/MEDIUM/LOW
    endpoint_score = Column(Float, nullable=True)    # From endpoint_scorer
    cvss = Column(Float, nullable=True)              # From NVD API
    epss = Column(Float, nullable=True)              # From EPSS API
    amplification_factor = Column(Float, default=1.0)

    # Plain English (from CWE lookup)
    plain_english_title = Column(String, nullable=True)
    plain_english_description = Column(Text, nullable=True)
    plain_english_impact = Column(Text, nullable=True)
    plain_english_fix = Column(Text, nullable=True)

    # Evidence
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    solution = Column(Text, nullable=True)

    # Raw data backup
    raw_data = Column(JSON, nullable=True)

    # Feedback status (set when human reviews)
    feedback_verdict = Column(String, nullable=True)   # "TP" or "FP"
    tp_probability = Column(Float, nullable=True)      # From ML model (0.0-1.0)
    feedback_flag = Column(String, nullable=True)      # "LIKELY_FALSE_POSITIVE", "CONFIRMED_PATTERN"

    created_at = Column(DateTime, default=datetime.utcnow)


class Feedback(Base):
    """
    Stores True Positive / False Positive verdicts from human reviewers.
    Every 50 new feedback events triggers a LogisticRegression retrain.
    """
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, index=True)           # References alerts.alert_id
    scan_id = Column(String, index=True)             # Which scan this alert came from
    user_id = Column(Integer, index=True)            # Who submitted the verdict
    endpoint = Column(String)                        # The URL path
    verdict = Column(String)                         # "TP" or "FP"
    app_type = Column(String, nullable=True)         # e-commerce, banking, saas, etc.
    user_notes = Column(Text, nullable=True)         # Optional reviewer notes

    # Agent context (what did the agent suggest before human decided?)
    agent_suggested_verdict = Column(String, nullable=True)  # "TP" or "FP"
    agent_confidence = Column(Float, nullable=True)          # 0.0-1.0
    agent_reasoning = Column(Text, nullable=True)            # Agent's explanation

    created_at = Column(DateTime, default=datetime.utcnow)


class ModelCheckpoint(Base):
    """
    Records metadata about each trained LogisticRegression model.
    A new row is added every time the model is retrained (every 50 events).
    """
    __tablename__ = "model_checkpoints"

    id = Column(Integer, primary_key=True, index=True)
    round = Column(Integer)                          # Training round (1, 2, 3, ...)
    f1_accuracy = Column(Float)                      # F1 score
    precision = Column(Float)                        # Precision metric
    recall = Column(Float)                           # Recall metric
    n_samples = Column(Integer)                      # Number of feedback samples used
    model_path = Column(String)                      # Path to saved .pkl file
    created_at = Column(DateTime, default=datetime.utcnow)


class UserMemory(Base):
    """
    Per-user memory of past corrections and patterns.
    PRIORITY CONTEXT — weighted 70% in the agent's prompt.

    When a human overrides the agent's suggestion, a correction
    is stored here with an embedding for semantic retrieval.
    """
    __tablename__ = "user_memories"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)            # Which user this memory belongs to
    alert_type = Column(String, index=True)          # "xss_reflected", "sqli", etc.
    cwe_id = Column(String, nullable=True)           # CWE identifier
    path_pattern = Column(String)                    # URL path of the alert
    app_type = Column(String, nullable=True)         # e-commerce, banking, etc.
    agent_verdict = Column(String)                   # What the agent suggested
    human_verdict = Column(String)                   # What the human decided
    human_notes = Column(Text, nullable=True)        # Why they disagreed
    risk_score_at_time = Column(Float, nullable=True)  # Risk score when reviewed
    embedding = Column(JSON, nullable=True)          # Sentence-transformer vector for similarity
    created_at = Column(DateTime, default=datetime.utcnow)


class GlobalMemoryStats(Base):
    """
    Community-wide aggregated intelligence.
    COMMUNITY CONTEXT — weighted 30% in the agent's prompt.

    Tracks TP/FP rates per (cwe_id, alert_type, app_type) combination
    across ALL users. Updated after every feedback event.
    """
    __tablename__ = "global_memory_stats"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, index=True)              # CWE identifier
    alert_type = Column(String, index=True)          # "xss_reflected", "sqli", etc.
    app_type = Column(String, nullable=True, index=True)  # e-commerce, banking, etc.
    total_reviews = Column(Integer, default=0)       # Total feedback events
    tp_count = Column(Integer, default=0)            # True Positive count
    fp_count = Column(Integer, default=0)            # False Positive count
    tp_rate = Column(Float, default=0.5)             # TP / total
    avg_risk_score_tp = Column(Float, nullable=True)  # Average risk score of TPs
    avg_risk_score_fp = Column(Float, nullable=True)  # Average risk score of FPs
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
