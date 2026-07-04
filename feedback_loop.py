import os
import joblib
import hashlib
from sqlalchemy.orm import Session
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from database_models import Alert, Feedback, ModelCheckpoint

class FeedbackEngine:
    """
    ML Fallback logic for the feedback loop. 
    Auto-trains a Logistic Regression model on human feedback verdicts (TP/FP).
    Predicts probability of True Positive for new alerts.
    """
    MODEL_PATH = "models/feedback_lr.pkl"
    RETRAIN_THRESHOLD = 50

    def __init__(self):
        self.model = None
        os.makedirs("models", exist_ok=True)
        if os.path.exists(self.MODEL_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
            except Exception as e:
                print(f"[!] Error loading feedback model: {e}")

    def record_feedback(self, db: Session, alert_id: str, verdict: str, user_id: int, notes: str = None) -> dict:
        """
        Record a human verdict on an alert. Triggers auto-retrain if threshold reached.
        """
        alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        # Create Feedback record
        fb = Feedback(
            alert_id=alert_id,
            scan_id=alert.scan_id,
            user_id=user_id,
            endpoint=alert.path,
            verdict=verdict,
            user_notes=notes
        )
        db.add(fb)

        # Update alert
        alert.feedback_verdict = verdict
        db.commit()

        # Check retrain threshold
        total_fb = db.query(Feedback).count()
        retrained = False
        metrics = None

        if total_fb > 0 and total_fb % self.RETRAIN_THRESHOLD == 0:
            print(f"[*] Reached {total_fb} feedback events. Auto-retraining ML model...")
            metrics = self._retrain(db)
            if metrics:
                retrained = True
                print(f"[+] Retrain complete. F1: {metrics['f1']:.2f}")

        return {
            "feedback_id": fb.id,
            "retrained": retrained,
            "metrics": metrics,
            "total_feedback": total_fb
        }

    def _build_feature_vector(self, alert_obj) -> list:
        """
        Extract numerical features from an alert dict or DB object.
        """
        if isinstance(alert_obj, dict):
            risk_score = alert_obj.get("risk_score") or 0.5
            ep_score = alert_obj.get("components", {}).get("endpoint_criticality") or 0.5
            cvss = alert_obj.get("components", {}).get("cvss") or 0.5
            epss = alert_obj.get("components", {}).get("epss") or 0.0
            amp = alert_obj.get("components", {}).get("amplification") or 1.0
            conf = alert_obj.get("confidence", "Low")
            src = alert_obj.get("source", "zap")
            typ = alert_obj.get("type", "")
        else:
            # SQLAlchemy object
            risk_score = alert_obj.risk_score or 0.5
            ep_score = alert_obj.endpoint_score or 0.5
            cvss = alert_obj.cvss or 0.5
            epss = alert_obj.epss or 0.0
            amp = alert_obj.amplification_factor or 1.0
            conf = alert_obj.confidence or "Low"
            src = alert_obj.source or "zap"
            typ = alert_obj.type or ""

        # Encode categoricals
        conf_map = {"High": 1.0, "Medium": 0.6, "Low": 0.3}
        conf_encoded = conf_map.get(conf, 0.3)
        src_encoded = 1.0 if src == "zap" else 0.0
        
        # Simple string hash for type
        type_hash = float(int(hashlib.md5(typ.encode()).hexdigest()[:8], 16) / 0xffffffff)

        return [risk_score, ep_score, cvss, epss, amp, conf_encoded, src_encoded, type_hash]

    def _retrain(self, db: Session) -> dict:
        """
        Train a LogisticRegression classifier on all feedback.
        """
        feedbacks = db.query(Feedback).all()
        # Need a decent sample size to train meaningfully
        if len(feedbacks) < 10:
            return None
            
        X = []
        y = []
        
        for fb in feedbacks:
            # We skip feedback if alert doesn't exist
            alert = db.query(Alert).filter(Alert.alert_id == fb.alert_id).first()
            if alert:
                X.append(self._build_feature_vector(alert))
                y.append(1 if fb.verdict == "TP" else 0)

        # Scikit-learn needs at least 2 classes
        if len(set(y)) < 2:
            return None

        # Train model with class balancing to handle skewed TP/FP rates
        model = LogisticRegression(class_weight="balanced")
        model.fit(X, y)
        self.model = model
        
        # Evaluate metrics on train set (in real world we'd split, but data is small)
        preds = model.predict(X)
        f1 = f1_score(y, preds)
        prec = precision_score(y, preds, zero_division=0)
        rec = recall_score(y, preds, zero_division=0)
        
        # Save model to disk
        joblib.dump(self.model, self.MODEL_PATH)
        
        # Save checkpoint to DB
        rounds = db.query(ModelCheckpoint).count() + 1
        ckpt = ModelCheckpoint(
            round=rounds,
            f1_accuracy=float(f1),
            precision=float(prec),
            recall=float(rec),
            n_samples=len(y),
            model_path=self.MODEL_PATH
        )
        db.add(ckpt)
        db.commit()
        
        return {
            "round": rounds,
            "f1": float(f1),
            "precision": float(prec),
            "recall": float(rec),
            "samples": len(y)
        }
        
    def predict_tp_probability(self, alert_dict: dict) -> float:
        """
        Predict probability (0.0 to 1.0) that a given alert is a True Positive.
        """
        if not self.model:
            return 0.5 # Unknown without a trained model

        features = self._build_feature_vector(alert_dict)
        
        # predict_proba returns [[P(FP), P(TP)]]
        probs = self.model.predict_proba([features])[0]
        return float(probs[1])
        
    def generate_learning_curve(self, db: Session) -> list:
        """
        Fetch historical checkpoint metrics to render learning curve chart in UI.
        """
        ckpts = db.query(ModelCheckpoint).order_by(ModelCheckpoint.round).all()
        return [{
            "round": c.round,
            "f1": c.f1_accuracy,
            "precision": c.precision,
            "recall": c.recall,
            "samples": c.n_samples,
            "created_at": c.created_at.isoformat()
        } for c in ckpts]
