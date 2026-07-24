import os
import json
import hashlib
from typing import Any, Optional
from functools import wraps
import redis

class CacheManager:
    """Centralized Redis cache with graceful degradation."""
    
    def __init__(self):
        self.redis_client = None
        self.is_available = False
        
        host = os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_PORT", 6379))
        
        try:
            self.redis_client = redis.Redis(host=host, port=port, db=0, decode_responses=True, socket_timeout=2)
            # Ping to check if Redis is actually up
            self.redis_client.ping()
            self.is_available = True
            print(f"[+] Redis Cache connected on {host}:{port}")
        except redis.ConnectionError:
            print(f"[!] Redis Cache connection failed. Caching is disabled.")
            self.redis_client = None
            self.is_available = False
            
    def get(self, key: str) -> Optional[Any]:
        """Get cached value, deserialize from JSON."""
        if not self.is_available or not self.redis_client:
            return None
        
        try:
            val = self.redis_client.get(key)
            if val is not None:
                return json.loads(val)
        except Exception as e:
            print(f"[!] Redis GET error for {key}: {e}")
        return None

    def set(self, key: str, value: Any, ttl_seconds: int = 3600):
        """Set cached value with TTL, serialize to JSON."""
        if not self.is_available or not self.redis_client:
            return
            
        try:
            # We serialize the value to JSON before storing
            json_val = json.dumps(value)
            self.redis_client.setex(key, ttl_seconds, json_val)
        except Exception as e:
            print(f"[!] Redis SET error for {key}: {e}")

    def delete(self, key: str):
        """Delete a single key."""
        if self.is_available and self.redis_client:
            try:
                self.redis_client.delete(key)
            except Exception as e:
                print(f"[!] Redis DELETE error for {key}: {e}")

    def clear_prefix(self, prefix: str):
        """Delete all keys matching a prefix (e.g. for targeted invalidation)."""
        if not self.is_available or not self.redis_client:
            return
            
        try:
            keys = self.redis_client.keys(f"{prefix}*")
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            print(f"[!] Redis CLEAR_PREFIX error for {prefix}: {e}")

# Module-level singleton instance
cache = CacheManager()

def redis_cache(prefix: str, ttl: int = 3600, cache_errors: bool = False):
    """
    A generic Redis cache decorator.
    - prefix: namespace like "vulnera:cvss" or "vulnera:epss"
    - ttl: expiry in seconds
    - cache_errors: if False, fallback or default error returns are NOT cached
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not cache.is_available:
                return func(*args, **kwargs)

            # Build a deterministic cache key based on function arguments
            # We filter out 'self' or 'cls' if it's the first argument to avoid hashing object instances
            relevant_args = args
            if args and hasattr(args[0], '__class__'):
                # Heuristic: if first arg is 'self', skip it for the hash
                relevant_args = args[1:]
                
            hash_input = json.dumps({"args": relevant_args, "kwargs": kwargs}, sort_keys=True)
            arg_hash = hashlib.sha256(hash_input.encode()).hexdigest()
            cache_key = f"{prefix}:{arg_hash}"
            
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
                
            # Cache miss, call the actual function
            result = func(*args, **kwargs)
            
            # Prevent caching error fallbacks if cache_errors is False
            # We define an error return as returning 0.5 or 0.1 for the risk scoring,
            # or returning None / empty string / empty dict.
            if not cache_errors:
                if result in (None, "", {}, [], 0.5, 0.1):
                    # Do not cache this result, it's likely a fallback value
                    return result
            
            # Cache the result
            cache.set(cache_key, result, ttl_seconds=ttl)
            return result
        return wrapper
    return decorator
