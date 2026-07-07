from sqlalchemy.orm import Session
from llm_adapter import LLMAdapter
from user_memory import UserMemory
from global_memory import GlobalMemory
from database_models import Alert

class AgentReviewer:
    """
    The main Agentic Reviewer. Uses Google Gemini combined with
    Priority User Memory and Global Community Context to review
    vulnerabilities and suggest True Positive / False Positive verdicts.
    """
    def __init__(self):
        self.llm = LLMAdapter(provider="gemini")
        self.user_memory = UserMemory()
        self.global_memory = GlobalMemory()

    def _build_system_prompt(self, user_context: str, global_context: str) -> str:
        return f"""You are Vulnera's elite security analysis agent. 
Your job is to review vulnerability scan findings and determine if they are likely a True Positive (real vulnerability) or False Positive (noise/scanner artifact).

{user_context}

{global_context}

When reviewing an alert, consider the priority user context heavily, followed by global consensus.

Respond strictly in valid JSON format with the following keys:
{{
  "verdict": "TP" or "FP",
  "confidence": <float between 0.0 and 1.0>,
  "reasoning": "<A 2-3 sentence explanation of your decision referencing the context>",
  "priority": "CRITICAL", "HIGH", "MEDIUM", or "LOW"
}}"""

    def review_alert(self, db: Session, alert: dict, user_id: int, app_type: str = "Unknown") -> dict:
        """
        Review a single alert using the LLM + Dual Memory.
        """
        # Retrieve memories
        user_context = self.user_memory.build_priority_prompt(db, user_id, alert, app_type)
        global_context = self.global_memory.build_community_prompt(db, alert, app_type)

        system_prompt = self._build_system_prompt(user_context, global_context)

        # Build alert text
        alert_text = f"""
## ALERT TO REVIEW
- Type: {alert.get('type', 'unknown')}
- CWE ID: {alert.get('cwe_id', 'unknown')}
- Path: {alert.get('path', '/')}
- Target App Type: {app_type}
- Original Scanner Risk: {alert.get('original_risk', 'Unknown')}
- AI Risk Score: {alert.get('risk_score', 0.5)}
- Endpoint Sensitivity: {alert.get('endpoint_score', 0.5)}
- Evidence/Snippet: {alert.get('evidence', '')}
- Description: {alert.get('description', '')}
"""
        
        # Call LLM
        response_json = self.llm.generate_json(system_prompt, alert_text)

        # Fallback if LLM fails
        if not response_json or "verdict" not in response_json:
            return {
                "suggested_verdict": "UNKNOWN",
                "confidence": 0.0,
                "reasoning": "Failed to get a valid response from the AI agent.",
                "priority": "LOW"
            }

        return {
            "suggested_verdict": response_json.get("verdict", "UNKNOWN"),
            "confidence": float(response_json.get("confidence", 0.5)),
            "reasoning": response_json.get("reasoning", ""),
            "priority": response_json.get("priority", "LOW")
        }

    def review_batch(self, db: Session, alerts: list, user_id: int, app_type: str = "Unknown") -> dict:
        """
        Review multiple alerts.
        """
        results = {}
        for alert in alerts:
            alert_id = alert.get("alert_id")
            if alert_id:
                res = self.review_alert(db, alert, user_id, app_type)
                results[alert_id] = res
        return results

    def handle_override(self, db: Session, alert_id: str, user_id: int, 
                        agent_verdict: str, human_verdict: str, 
                        human_notes: str, app_type: str = "Unknown"):
        """
        Called when a human submits a verdict. 
        Stores correction in user memory (if they disagreed with agent).
        Updates global community stats.
        """
        # Fetch alert to get context
        db_alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
        if not db_alert:
            return
            
        alert_dict = {
            "type": db_alert.type,
            "cwe_id": db_alert.cwe_id,
            "path": db_alert.path,
            "risk_score": db_alert.risk_score
        }

        # 1. Store user correction if human disagreed with agent
        if agent_verdict and human_verdict != agent_verdict:
            self.user_memory.store_correction(
                db=db, 
                user_id=user_id, 
                alert=alert_dict, 
                agent_verdict=agent_verdict, 
                human_verdict=human_verdict, 
                human_notes=human_notes, 
                app_type=app_type
            )

        # 2. Update global stats (always update on any feedback)
        self.global_memory.update_stats(db, alert_dict, human_verdict, app_type)
