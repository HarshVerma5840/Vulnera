"""
endpoint_scorer.py — Phase 1: AI Endpoint Risk Scoring

Calculates how sensitive/critical a specific URL path is using a 3-layer approach:
1. App-Type Multipliers (Business logic)
2. Neural Semantic Clustering (all-MiniLM-L6-v2 + KMeans)
3. Regex Heuristics (Fallback)
"""

import os
import re
import json
import pickle

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None

class EndpointScorer:
    """Scores endpoint paths from 0.0 to 1.0 based on criticality."""
    
    def __init__(self, 
                 model_path="models/kmeans.pkl", 
                 rules_path="data/app_type_rules.json"):
        
        self.kmeans = None
        self.cluster_mapping = {}
        self.transformer = None
        self.app_rules = {}
        
        # Load business logic rules
        self._load_app_rules(rules_path)
        
        # Load AI models
        self._load_models(model_path)
        
    def _load_app_rules(self, rules_path):
        """Load business logic multipliers."""
        if os.path.exists(rules_path):
            try:
                with open(rules_path, 'r') as f:
                    self.app_rules = json.load(f)
            except Exception as e:
                print(f"[!] Error loading app rules: {e}")
                
    def _load_models(self, model_path):
        """Load KMeans model and SentenceTransformer."""
        if os.path.exists(model_path) and SentenceTransformer is not None:
            try:
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.kmeans = data.get("kmeans")
                    self.cluster_mapping = data.get("cluster_mapping", {})
                    
                    transformer_name = data.get("transformer_model_name", "all-MiniLM-L6-v2")
                    self.transformer = SentenceTransformer(transformer_name)
                    print(f"[+] Loaded endpoint scoring AI: {transformer_name}")
            except Exception as e:
                print(f"[!] Failed to load ML models: {e}")
                
    def _clean_path(self, path: str) -> str:
        """Strip punctuation and IDs to extract semantic meaning."""
        p = str(path).lower()
        p = re.sub(r'\.[a-z0-9]+$', '', p)  # Remove extension
        p = re.sub(r'[/_\-]', ' ', p)       # Replace separators with space
        p = re.sub(r'\b[a-f0-9]{8,}\b', '', p) # Remove UUIDs/hashes
        p = re.sub(r'\b\d+\b', '', p)       # Remove pure numbers
        return " ".join(p.split())
        
    def _score_regex_fallback(self, clean_path: str) -> tuple:
        """
        Layer 3: Simple regex fallback if AI fails or isn't loaded.
        Returns: (score, confidence)
        """
        patterns = {
            r'\b(admin|root|config|system|backup|setup)\b': 0.9,
            r'\b(login|auth|password|token|oauth|credential)\b': 0.8,
            r'\b(api|v1|v2|graphql|rest)\b': 0.6,
            r'\b(user|profile|account|billing|payment)\b': 0.6,
            r'\b(data|export|download|upload)\b': 0.5,
            r'\b(css|js|img|static|assets|font|icon)\b': 0.1,
            r'\b(about|contact|home|public|faq)\b': 0.2
        }
        
        for pattern, score in patterns.items():
            if re.search(pattern, clean_path):
                return (score, "medium")
                
        return (0.5, "low") # Default unknown
        
    def _score_neural(self, clean_path: str) -> tuple:
        """
        Layer 2: SentenceTransformer + KMeans clustering.
        Returns: (score, cluster_label) or (None, None)
        """
        if not self.transformer or not self.kmeans or len(clean_path) < 3:
            return None, None
            
        try:
            # 1. Embed the path
            embedding = self.transformer.encode([clean_path])
            
            # 2. Predict cluster
            cluster_id = self.kmeans.predict(embedding)[0]
            
            # 3. Lookup score
            cluster_info = self.cluster_mapping.get(cluster_id)
            if cluster_info:
                return cluster_info["score"], cluster_info["label"]
                
        except Exception as e:
            print(f"[!] Neural scoring error for '{clean_path}': {e}")
            
        return None, None

    def score_endpoint(self, path: str, app_type: str = None) -> dict:
        """
        Main entry point. Scores a path using the 3-layer architecture.
        """
        clean_path = self._clean_path(path)
        
        # 1. Base Score (Try Neural first, then Fallback)
        neural_score, cluster_label = self._score_neural(clean_path)
        
        if neural_score is not None:
            base_score = neural_score
            method = "neural"
            confidence = "high"
        else:
            base_score, confidence = self._score_regex_fallback(clean_path)
            method = "regex_fallback"
            cluster_label = "unknown"
            
        # 2. App-Type Multiplier (Business Logic)
        multiplier = 1.0
        if app_type and app_type in self.app_rules:
            rules = self.app_rules[app_type].get("multipliers", {})
            for pattern, boost in rules.items():
                if re.search(r'\b(' + pattern + r')\b', clean_path):
                    multiplier = boost
                    break
                    
        # 3. Final Calculation
        final_score = base_score * multiplier
        final_score = min(1.0, max(0.0, final_score)) # Clamp between 0 and 1
        
        return {
            "path": path,
            "clean_path": clean_path,
            "score": round(final_score, 3),
            "base_score": round(base_score, 3),
            "method": method,
            "cluster": cluster_label,
            "app_type_boost": multiplier,
            "confidence": confidence
        }

if __name__ == "__main__":
    # Quick standalone test
    scorer = EndpointScorer()
    
    test_paths = [
        "/api/v1/admin/delete_user",
        "/wp-admin/config.php",
        "/auth/reset-password",
        "/static/images/logo.png",
        "/blog/2023/updates",
        "/a/b/c/d/e" # obfuscated
    ]
    
    print("\n[Endpoint Scoring Test]")
    print(f"{'PATH':<30} | {'SCORE':<5} | {'METHOD':<15} | {'CLUSTER':<10}")
    print("-" * 70)
    
    for p in test_paths:
        result = scorer.score_endpoint(p)
        print(f"{p:<30} | {result['score']:<5.2f} | {result['method']:<15} | {result['cluster']:<10}")
