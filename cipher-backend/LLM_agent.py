import json
import random
import time
import traceback
import os
from google import genai

# 🔑 Use environment variable for production security
api_key = os.getenv("GEMINI_API_KEY", "AIzaSyBovTgenVXXmHoazsp7kPwiznUvJSA1B-4")
client = genai.Client(api_key=api_key)

def _call_gemini_with_retry(user_input: str, retries: int = 2):
    """
    Call Gemini with manual exponential backoff retry logic.
    """
    prompt = f"""
You are an AI Security System.

Analyze the user prompt and return ONLY JSON:

{{
  "prediction": "SAFE or MALICIOUS",
  "risk_score": 0-100,
  "risk_level": "LOW / MEDIUM / HIGH",
  "reason": "short explanation",
  "matched_keywords": []
}}

User Prompt: {user_input}
"""
    last_error = None
    for i in range(retries):
        try:
            # Using standard gemini-1.5-flash for common API compatibility
            response = client.models.generate_content(
                model="gemini-1.5-flash", 
                contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            last_error = e
            # Only retry on 429; everything else (like 404) should fail immediately to hit fallback
            if "429" in str(e):
                wait_time = (2 ** (i + 1)) + (random.random() * 2)
                print(f"Rate limited (429). Retrying in {wait_time:.2f}s...")
                time.sleep(wait_time)
                continue
            break # 404 or other errors break out immediately to the fallback
    
    if last_error:
        raise last_error
    return "{}"

def analyze_input(user_input: str):
    """
    LLM agent for security analysis.
    Output will be JSON string.
    """
    try:
        text = _call_gemini_with_retry(user_input)
        
        # Clean up any potential markdown code blocks returned by Gemini
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
            
        if text.endswith("```"):
            text = text[:-3]
        
        return json.loads(text.strip())
    except Exception as e:
        print(f"LLM Logic Error/Fallback Activated: {e}")
        
        # Determine fallback based on simple heuristics if LLM fails (e.g. 429, 404, etc.)
        lower_input = user_input.lower()
        if any(w in lower_input for w in ["ignore", "jailbreak", "dan", "bypass", "unrestricted", "override"]):
             return {
                "prediction": "MALICIOUS",
                "risk_score": 92,
                "risk_level": "HIGH",
                "reason": f"CIPHER HEURISTIC: Critical adversarial patterns detected in '{user_input[:20]}...'. (LLM Engine Offline)",
                "matched_keywords": ["adversarial_pattern_detected"]
            }
        
        return {
            "prediction": "SAFE",
            "risk_score": 0,
            "risk_level": "LOW",
            "reason": "CIPHER HEURISTIC: No critical threat patterns found. (LLM Engine Offline)",
            "matched_keywords": []
        }