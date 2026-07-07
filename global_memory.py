from sqlalchemy.orm import Session
from datetime import datetime
from database_models import GlobalMemoryStats

class GlobalMemory:
    """
    Manages the Community Context.
    Aggregates True Positive / False Positive rates across ALL users.
    """

    def update_stats(self, db: Session, alert: dict, verdict: str, app_type: str = "Unknown"):
        """
        Update the community consensus for this specific (CWE, alert type, app type) combo.
        Called every time any user submits feedback.
        """
        cwe_id = alert.get("cwe_id", "unknown")
        alert_type = alert.get("type", "unknown")
        risk_score = alert.get("risk_score", 0.0)

        # Try to find existing stats row
        stat = db.query(GlobalMemoryStats).filter(
            GlobalMemoryStats.cwe_id == cwe_id,
            GlobalMemoryStats.alert_type == alert_type,
            GlobalMemoryStats.app_type == app_type
        ).first()

        if not stat:
            # Create new row
            stat = GlobalMemoryStats(
                cwe_id=cwe_id,
                alert_type=alert_type,
                app_type=app_type,
                total_reviews=0,
                tp_count=0,
                fp_count=0,
                avg_risk_score_tp=0.0,
                avg_risk_score_fp=0.0
            )
            db.add(stat)

        # Update counts
        stat.total_reviews += 1
        
        if verdict == "TP":
            # Running average for TP risk score
            current_total = stat.avg_risk_score_tp * stat.tp_count if stat.avg_risk_score_tp else 0
            stat.tp_count += 1
            stat.avg_risk_score_tp = (current_total + risk_score) / stat.tp_count
        else:
            # Running average for FP risk score
            current_total = stat.avg_risk_score_fp * stat.fp_count if stat.avg_risk_score_fp else 0
            stat.fp_count += 1
            stat.avg_risk_score_fp = (current_total + risk_score) / stat.fp_count

        stat.tp_rate = stat.tp_count / stat.total_reviews
        stat.last_updated = datetime.utcnow()
        db.commit()

    def get_consensus(self, db: Session, cwe_id: str, alert_type: str, app_type: str = "Unknown") -> dict:
        """
        Determine what the community thinks about this type of alert.
        """
        stat = db.query(GlobalMemoryStats).filter(
            GlobalMemoryStats.cwe_id == cwe_id,
            GlobalMemoryStats.alert_type == alert_type,
            GlobalMemoryStats.app_type == app_type
        ).first()

        if not stat or stat.total_reviews < 3:
            return {
                "consensus": "UNKNOWN",
                "confidence": "LOW",
                "tp_rate": 0.5,
                "total_reviews": stat.total_reviews if stat else 0
            }

        # Determine consensus
        consensus = "CONTESTED"
        if stat.tp_rate >= 0.7:
            consensus = "LIKELY_TP"
        elif stat.tp_rate <= 0.3:
            consensus = "LIKELY_FP"

        # Determine statistical confidence
        confidence = "LOW"
        if stat.total_reviews >= 50:
            confidence = "HIGH"
        elif stat.total_reviews >= 10:
            confidence = "MEDIUM"

        return {
            "consensus": consensus,
            "confidence": confidence,
            "tp_rate": stat.tp_rate,
            "fp_rate": 1.0 - stat.tp_rate,
            "total_reviews": stat.total_reviews,
            "avg_tp_score": stat.avg_risk_score_tp,
            "avg_fp_score": stat.avg_risk_score_fp
        }

    def get_top_fp_patterns(self, db: Session, app_type: str = "Unknown", limit=5) -> list:
        """
        What are the most commonly false-positive alert types for this app type?
        """
        stats = db.query(GlobalMemoryStats).filter(
            GlobalMemoryStats.app_type == app_type,
            GlobalMemoryStats.total_reviews >= 5,
            GlobalMemoryStats.tp_rate <= 0.4
        ).order_by(GlobalMemoryStats.tp_rate.asc()).limit(limit).all()
        
        return [s.alert_type for s in stats]

    def build_community_prompt(self, db: Session, alert: dict, app_type: str = "Unknown") -> str:
        """
        Build the community context block for the LLM prompt.
        """
        cwe_id = alert.get("cwe_id", "unknown")
        alert_type = alert.get("type", "unknown")
        
        consensus = self.get_consensus(db, cwe_id, alert_type, app_type)
        top_fps = self.get_top_fp_patterns(db, app_type)
        
        prompt = "## Community Intelligence (GLOBAL CONTEXT)\\n"
        
        if consensus["consensus"] == "UNKNOWN":
            prompt += f"Not enough community data yet for '{alert_type}' (CWE {cwe_id}) on '{app_type}' applications.\\n"
        else:
            tp_pct = round(consensus["tp_rate"] * 100)
            prompt += f"Across {consensus['total_reviews']} community reviews for '{alert_type}' (CWE {cwe_id}) on '{app_type}' applications:\\n"
            prompt += f"- True Positive Rate: {tp_pct}%\\n"
            prompt += f"- False Positive Rate: {100 - tp_pct}%\\n"
            prompt += f"- Statistical Confidence: {consensus['confidence']}\\n"
            prompt += f"- Community Consensus: {consensus['consensus']}\\n"
            
        if top_fps:
            prompt += f"\\nNote: The community frequently marks these alert types as False Positives on '{app_type}' apps: {', '.join(top_fps)}\\n"
            
        return prompt
