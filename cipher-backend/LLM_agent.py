# LLM_agent.py
import re
import os
import time
import json
import logging
from google import genai
from google.genai.errors import ClientError, ServerError

logger = logging.getLogger("cipher.llm_agent")

# Load API key from .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_API_KEY        = os.getenv("GOOGLE_API_KEY", "AIzaSyChpuxNBZQt3tOhpsvFJiBBmyDv6TNX91o")
_MODEL_PRIMARY  = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
_MODEL_FALLBACK = "gemini-flash-latest"

client = genai.Client(api_key=_API_KEY)

# Strip markdown code fences (```json ... ``` or ``` ... ```)
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

_FALLBACK_RESPONSE = {
    "prediction":       "SAFE",
    "risk_score":       0,
    "risk_level":       "LOW",
    "reason":           "LLM unavailable; rule-engine score used.",
    "matched_keywords": [],
}


def _call_gemini(prompt: str, model: str, retries: int = 1) -> str:
    """Call Gemini with simple retry on 429/503."""
    delay = 3
    for attempt in range(retries + 1):
        try:
            response = client.models.generate_content(model=model, contents=prompt)
            return response.text or ""
        except (ClientError, ServerError) as e:
            is_retryable = "429" in str(e) or "503" in str(e) or "RESOURCE_EXHAUSTED" in str(e) or "UNAVAILABLE" in str(e)
            if is_retryable and attempt < retries:
                logger.warning(f"[LLM Agent] {model} rate-limited/unavailable, retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2
                continue
            raise


def analyze_input(user_input: str) -> dict:
    """
    Analyze user input for security risk via Gemini LLM.

    Returns dict with keys:
        prediction       – "SAFE" or "MALICIOUS"
        risk_score       – int 0-100
        risk_level       – "LOW" / "MEDIUM" / "HIGH"
        reason           – short explanation string
        matched_keywords – list[str]
    """
    prompt = f"""You are an AI Security System.

Analyze the user prompt below and respond with ONLY valid JSON — no markdown fences,
no commentary, no extra text.

Required JSON format:
{{
  "prediction": "SAFE",
  "risk_score": 0,
  "risk_level": "LOW",
  "reason": "short explanation",
  "matched_keywords": []
}}

Rules:
- prediction must be exactly "SAFE" or "MALICIOUS"
- risk_score must be an integer 0-100
- risk_level must be exactly "LOW", "MEDIUM", or "HIGH"
- matched_keywords is a list of strings (can be empty)
- Return ONLY the JSON object, nothing else

User Prompt: {user_input}
"""
    raw = ""
    # Try primary model, fall back to secondary on rate-limit/unavailable
    for model in (_MODEL_PRIMARY, _MODEL_FALLBACK):
        try:
            raw = _call_gemini(prompt, model)
            break
        except Exception as e:
            logger.error(f"[LLM Agent] {model} failed: {type(e).__name__}: {e}")
            raw = ""

    if not raw:
        return dict(_FALLBACK_RESPONSE)

    try:
        clean = _CODE_FENCE_RE.sub("", raw).strip()
        if not clean:
            logger.warning("[LLM Agent] Empty response from Gemini.")
            return dict(_FALLBACK_RESPONSE)

        parsed: dict = json.loads(clean)
        parsed["risk_score"]       = int(parsed.get("risk_score", 0))
        parsed["prediction"]       = str(parsed.get("prediction", "SAFE")).upper()
        parsed["risk_level"]       = str(parsed.get("risk_level", "LOW")).upper()
        parsed.setdefault("reason", "")
        parsed.setdefault("matched_keywords", [])
        return parsed

    except json.JSONDecodeError as e:
        logger.warning(f"[LLM Agent] JSON parse error: {e} — raw: {raw[:300]}")
        return dict(_FALLBACK_RESPONSE)


# ===========================
# Terminal testing
# ===========================
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    print(f"=== LLM Agent Test (primary: {_MODEL_PRIMARY}, fallback: {_MODEL_FALLBACK}) ===")
    while True:
        user_input = input("\nEnter prompt (or 'exit' to quit): ")
        if user_input.lower() == "exit":
            break
        result = analyze_input(user_input)
        print("\n🚀 RESULT:")
        print(json.dumps(result, indent=2))
