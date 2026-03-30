import re

def detect_harmful_intent(prompt: str) -> dict:
    """
    HARM DETECTION ENGINE (Layer 2)
    Detects severe harmful intent including violence, terrorism, and illegal acts.
    """
    harmful_keywords = [
        r"\bkill\b",
        r"\bmurder\b",
        r"\bsuicide\b",
        r"\bbomb\b",
        r"\battack\b",
        r"\bterrorist\b",
        r"\bpoison\b",
        r"\bassassinate\b",
        r"\bshoot\b",
        r"\bstrangle\b",
    ]
    
    prompt_lower = prompt.lower()
    
    for kw in harmful_keywords:
        if re.search(kw, prompt_lower):
            return {
                "harmDetected": True,
                "riskScore": 85,
                "decision": "BLOCK",
                "matched_keyword": kw.replace(r"\b", "")
            }
            
    return {
        "harmDetected": False,
        "riskScore": 0,
        "decision": "ALLOW",
        "matched_keyword": None
    }
