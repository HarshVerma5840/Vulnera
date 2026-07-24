import os
import json
import google.generativeai as genai
from cache_manager import redis_cache

class LLMAdapter:
    """Wraps Google Gemini API with basic retry/parsing logic."""

    def __init__(self, provider="gemini"):
        self.provider = provider
        self.model = None
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            print("[!] GEMINI_API_KEY not found in environment.")
        else:
            genai.configure(api_key=api_key)
            # gemini-2.0-flash is the latest fast free-tier model
            self.model = genai.GenerativeModel('gemini-2.5-flash')

    @redis_cache(prefix="llm_text", ttl=21600, cache_errors=False)
    def generate(self, system_prompt: str, user_prompt: str, temperature: float = 0.3) -> str:
        """Send a prompt and get a text response."""
        if not self.model:
            return ""
            
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        try:
            response = self.model.generate_content(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=temperature,
                )
            )
            return response.text
        except Exception as e:
            print(f"[!] Error calling Gemini API: {e}")
            return ""

    @redis_cache(prefix="llm_json", ttl=21600, cache_errors=False)
    def generate_json(self, system_prompt: str, user_prompt: str) -> dict:
        """Send a prompt and parse structured JSON response."""
        if not self.model:
            return {}
            
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        try:
            response = self.model.generate_content(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                )
            )
            text = response.text.strip()
            # In case the model wraps it in markdown blocks
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
                
            return json.loads(text.strip())
        except Exception as e:
            print(f"[!] Error calling Gemini API (JSON): {e}")
            return {}
