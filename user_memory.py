import json
import numpy as np
from sqlalchemy.orm import Session
from database_models import UserMemory as DBUserMemory

try:
    from sentence_transformers import SentenceTransformer
    # We use a lightweight model for fast embeddings.
    # If it was already downloaded for endpoint_scorer, it will load instantly from cache.
    _transformer_model = SentenceTransformer("all-MiniLM-L6-v2")
except ImportError:
    _transformer_model = None
    print("[!] sentence_transformers not installed. UserMemory will not use embeddings.")

def cosine_similarity(v1, v2):
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    if norm_v1 == 0 or norm_v2 == 0:
        return 0.0
    return dot_product / (norm_v1 * norm_v2)

class UserMemory:
    """
    Manages the Priority Context (this specific user's past behavior).
    Stores corrections when human overrides the agent, and retrieves similar 
    past corrections using semantic embeddings.
    """
    
    def __init__(self):
        self.model = _transformer_model

    def _get_embedding(self, text: str) -> list:
        if not self.model:
            return []
        vector = self.model.encode(text)
        return vector.tolist()

    def _build_context_string(self, alert_type, cwe_id, path, app_type) -> str:
        # We embed a simple descriptive string of the vulnerability context
        return f"Type: {alert_type}. CWE: {cwe_id}. Path: {path}. App: {app_type}."

    def store_correction(self, db: Session, user_id: int, alert: dict, 
                         agent_verdict: str, human_verdict: str, 
                         human_notes: str, app_type: str = "Unknown"):
        """
        Store a correction when the user disagrees with the agent.
        """
        alert_type = alert.get("type", "unknown")
        cwe_id = alert.get("cwe_id", "unknown")
        path = alert.get("path", "/")
        risk_score = alert.get("risk_score", 0.0)

        context_str = self._build_context_string(alert_type, cwe_id, path, app_type)
        embedding = self._get_embedding(context_str)

        memory = DBUserMemory(
            user_id=user_id,
            alert_type=alert_type,
            cwe_id=cwe_id,
            path_pattern=path,
            app_type=app_type,
            agent_verdict=agent_verdict,
            human_verdict=human_verdict,
            human_notes=human_notes,
            risk_score_at_time=risk_score,
            embedding=embedding
        )
        db.add(memory)
        db.commit()
        return memory.id

    def retrieve_similar(self, db: Session, user_id: int, alert: dict, app_type: str = "Unknown", top_k=5) -> list:
        """
        Find this user's most relevant past corrections using cosine similarity.
        """
        if not self.model:
            return []

        alert_type = alert.get("type", "unknown")
        cwe_id = alert.get("cwe_id", "unknown")
        path = alert.get("path", "/")
        
        context_str = self._build_context_string(alert_type, cwe_id, path, app_type)
        query_vector = self.model.encode(context_str)

        # Fetch all memories for this user
        memories = db.query(DBUserMemory).filter(DBUserMemory.user_id == user_id).all()
        
        results = []
        for mem in memories:
            if mem.embedding and len(mem.embedding) > 0:
                sim = cosine_similarity(query_vector, np.array(mem.embedding))
                results.append({
                    "alert_type": mem.alert_type,
                    "cwe_id": mem.cwe_id,
                    "path_pattern": mem.path_pattern,
                    "agent_said": mem.agent_verdict,
                    "user_said": mem.human_verdict,
                    "user_notes": mem.human_notes,
                    "similarity": float(sim)
                })

        # Sort by similarity descending
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

    def get_user_patterns(self, db: Session, user_id: int) -> dict:
        """
        Summarize this user's overall patterns.
        """
        memories = db.query(DBUserMemory).filter(DBUserMemory.user_id == user_id).all()
        
        total = len(memories)
        if total == 0:
            return {"total_overrides": 0, "common_fp_types": []}
            
        fp_types = {}
        for mem in memories:
            if mem.human_verdict == "FP":
                fp_types[mem.alert_type] = fp_types.get(mem.alert_type, 0) + 1
                
        sorted_fps = sorted(fp_types.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "total_overrides": total,
            "common_fp_types": [item[0] for item in sorted_fps[:3]]
        }

    def build_priority_prompt(self, db: Session, user_id: int, alert: dict, app_type: str = "Unknown") -> str:
        """
        Build the priority context block for the LLM prompt.
        """
        similar_corrections = self.retrieve_similar(db, user_id, alert, app_type)
        patterns = self.get_user_patterns(db, user_id)
        
        prompt = "## This User's History (PRIORITY - weight this heavily)\\n"
        
        if patterns["total_overrides"] == 0:
            prompt += "No past corrections from this user yet. They generally agree with agent suggestions.\\n"
            return prompt
            
        prompt += f"- Total past overrides by this user: {patterns['total_overrides']}\\n"
        if patterns["common_fp_types"]:
            prompt += f"- Alert types this user frequently overrides as False Positive: {', '.join(patterns['common_fp_types'])}\\n"
            
        if similar_corrections:
            # Only include highly similar ones
            relevant = [c for c in similar_corrections if c["similarity"] > 0.65]
            if relevant:
                prompt += "\\nRelevant past corrections for similar alerts:\\n"
                for i, r in enumerate(relevant):
                    prompt += f"{i+1}. The user marked a '{r['alert_type']}' on '{r['path_pattern']}' as {r['user_said']} (overriding agent's {r['agent_said']}).\\n"
                    if r["user_notes"]:
                        prompt += f"   User's explanation: \\\"{r['user_notes']}\\\"\\n"
            else:
                prompt += "\\nNo highly similar past corrections for this specific vulnerability type/path.\\n"
                
        return prompt
