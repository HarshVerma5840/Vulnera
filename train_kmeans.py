"""
train_kmeans.py — Trains the AI endpoint clustering model

Downloads common endpoint lists from SecLists, embeds them using
sentence-transformers, clusters them with K-Means, and saves the
model to models/kmeans.pkl for fast inference during scans.
"""

import os
import re
import time
import pickle
import requests
from sklearn.cluster import KMeans

# Attempt to import sentence_transformers
try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    print("[!] sentence-transformers not installed.")
    print("    Run: pip install sentence-transformers scikit-learn")
    import sys
    sys.exit(1)

# URLs for training data (SecLists)
SECLISTS = {
    "api": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    "raft": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt",
    "common": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
}

# The clustering architecture
N_CLUSTERS = 20
MODEL_NAME = 'all-MiniLM-L6-v2'
OUTPUT_DIR = "models"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "kmeans.pkl")

# Predefined base scores for certain semantic concepts
# We map clusters to these scores after training based on keywords
CLUSTER_SCORES = {
    "admin": 0.95,
    "auth": 0.85,
    "api": 0.70,
    "user": 0.60,
    "data": 0.55,
    "public": 0.20,
    "static": 0.10,
    "default": 0.50
}

def clean_path(path: str) -> str:
    """Strip punctuation and file extensions to extract semantic meaning."""
    # Remove file extensions (.php, .html, .js)
    p = re.sub(r'\.[a-zA-Z0-9]+$', '', path)
    # Replace slashes, dashes, underscores with spaces
    p = re.sub(r'[/_\-]', ' ', p)
    # Remove random numbers (often IDs)
    p = re.sub(r'\b\d+\b', '', p)
    # Lowercase and trim
    return " ".join(p.lower().split())

def download_data():
    """Download and clean data from SecLists."""
    print("[*] Downloading training data from SecLists...")
    raw_paths = set()
    
    for name, url in SECLISTS.items():
        try:
            print(f"    -> Downloading {name} list...")
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        raw_paths.add(line)
            else:
                print(f"    [!] Failed to download {name}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"    [!] Error downloading {name}: {e}")
            
    print(f"[+] Downloaded {len(raw_paths)} unique paths.")
    
    # Clean paths
    clean_paths = set()
    for path in raw_paths:
        cleaned = clean_path(path)
        if cleaned and len(cleaned) > 2:
            clean_paths.add(cleaned)
            
    print(f"[+] Cleaned dataset: {len(clean_paths)} unique semantic phrases.")
    
    # Limit dataset size to ensure fast training (< 2 mins)
    dataset = list(clean_paths)
    if len(dataset) > 10000:
        print("    -> Truncating dataset to 10,000 samples for speed...")
        dataset = dataset[:10000]
        
    return dataset

def auto_label_clusters(kmeans, embeddings, dataset):
    """
    Assign semantic labels and base scores to the completely unsupervised
    clusters based on the words that ended up inside them.
    """
    labels = kmeans.labels_
    cluster_texts = {i: [] for i in range(N_CLUSTERS)}
    
    # Group words by cluster
    for text, label in zip(dataset, labels):
        cluster_texts[label].append(text)
        
    cluster_scores = {}
    
    # Analyze each cluster to determine its dominant theme
    for i in range(N_CLUSTERS):
        texts = cluster_texts[i]
        text_blob = " ".join(texts)
        
        # Simple heuristic mapping
        if any(w in text_blob for w in ['admin', 'root', 'config', 'setup', 'system']):
            score = CLUSTER_SCORES["admin"]
            label = "admin"
        elif any(w in text_blob for w in ['login', 'auth', 'password', 'token', 'session', 'oauth']):
            score = CLUSTER_SCORES["auth"]
            label = "auth"
        elif any(w in text_blob for w in ['api', 'v1', 'v2', 'graphql', 'rest']):
            score = CLUSTER_SCORES["api"]
            label = "api"
        elif any(w in text_blob for w in ['user', 'profile', 'account']):
            score = CLUSTER_SCORES["user"]
            label = "user"
        elif any(w in text_blob for w in ['data', 'export', 'download', 'database', 'sql']):
            score = CLUSTER_SCORES["data"]
            label = "data"
        elif any(w in text_blob for w in ['css', 'js', 'img', 'static', 'assets', 'font', 'icon']):
            score = CLUSTER_SCORES["static"]
            label = "static"
        elif any(w in text_blob for w in ['about', 'contact', 'home', 'public', 'blog']):
            score = CLUSTER_SCORES["public"]
            label = "public"
        else:
            score = CLUSTER_SCORES["default"]
            label = "unknown"
            
        cluster_scores[i] = {
            "score": score,
            "label": label,
            "sample_words": texts[:5]
        }
        
    return cluster_scores

def main():
    start_time = time.time()
    
    # 1. Download & Clean
    dataset = download_data()
    if not dataset:
        print("[-] No data downloaded. Cannot train.")
        sys.exit(1)
        
    # 2. Load Model
    print(f"\n[*] Loading Transformer model ({MODEL_NAME})...")
    # This downloads the ~80MB model automatically if not cached
    model = SentenceTransformer(MODEL_NAME)
    
    # 3. Vectorization
    print("[*] Vectorizing paths (this takes 15-20 seconds)...")
    vec_start = time.time()
    embeddings = model.encode(dataset, show_progress_bar=True)
    print(f"[+] Vectorization complete in {time.time() - vec_start:.1f}s")
    
    # 4. K-Means Clustering
    print(f"\n[*] Training K-Means ({N_CLUSTERS} clusters)...")
    km_start = time.time()
    kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=42, n_init=10)
    kmeans.fit(embeddings)
    print(f"[+] K-Means trained in {time.time() - km_start:.1f}s")
    
    # 5. Labeling
    print("\n[*] Auto-labeling clusters...")
    cluster_mapping = auto_label_clusters(kmeans, embeddings, dataset)
    
    # Print cluster summary
    for i, info in cluster_mapping.items():
        print(f"    Cluster {i:02d} [{info['label']:>7} / {info['score']:.2f}]: {', '.join(info['sample_words'])}")
        
    # 6. Save Model
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    model_data = {
        "kmeans": kmeans,
        "cluster_mapping": cluster_mapping,
        "transformer_model_name": MODEL_NAME,
        "trained_on": len(dataset),
        "timestamp": time.time()
    }
    
    with open(OUTPUT_FILE, 'wb') as f:
        pickle.dump(model_data, f)
        
    print(f"\n[+] SUCCESS: Model saved to {OUTPUT_FILE}")
    print(f"[+] Total elapsed time: {time.time() - start_time:.1f} seconds")

if __name__ == "__main__":
    main()
