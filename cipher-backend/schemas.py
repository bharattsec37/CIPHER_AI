from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any


# ---------------------------------------------------------------------------
# CIPHER Single-Agent Models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000, description="The prompt to analyze")


class AnalyzeResponse(BaseModel):
    # ── ANTI-GRAVITY Strict JSON Fields ──────────────────────────────────────
    risk_score: float = Field(..., ge=0, le=100)  # Changed to float for fusion
    decision: Literal["ALLOW", "SANDBOX", "BLOCK"]
    harmDetected: bool = Field(default=False)
    fusion_breakdown: Optional[Dict[str, Any]] = None
    categories_triggered: List[str] = Field(default_factory=list, description="ANTI-GRAVITY categories hit")
    reason: str = Field(description="Concise human-readable reason for decision")
    shadow_mode: bool = Field(default=False, description="True if attacker is being silently misdirected")
    # ── Extended Dashboard Fields ────────────────────────────────────────────
    prompt: str
    signals: List[str] = Field(default_factory=list, description="Detected threat signal tags")
    behavior_status: Literal["Normal", "Suspicious", "Malicious"]
    attack_type: Optional[str] = None
    confidence: int = Field(..., ge=0, le=100, description="Detection confidence 0–100")
    triggered_rules: List[str] = Field(default_factory=list)
    explanation: str
    safe_rewrite: Optional[str] = None
    category_scores: Optional[Dict[str, float]] = Field(default=None, description="Per-category risk scores")


class HealthResponse(BaseModel):
    status: str
    version: str
    engine: str
    total_rules: int
    categories: int


class StatsResponse(BaseModel):
    engine_version: str
    total_rules: int
    categories: List[str]
    category_rule_counts: dict
    scoring: dict


# ---------------------------------------------------------------------------
# Multi-Agent System Models
# ---------------------------------------------------------------------------

class MultiAgentRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000, description="Prompt to analyze through multi-agent pipeline")
    session_id: Optional[str] = Field(
        default=None,
        description="Session identifier for behavioral tracking. Auto-generated if omitted."
    )


class AgentResult(BaseModel):
    agent: str
    summary: str
    # Allow arbitrary extra fields per agent
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# LLM Agent Native Models
# ---------------------------------------------------------------------------

class LLMAnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000, description="Prompt for LLM to analyze")

class LLMAnalyzeResponse(BaseModel):
    prediction: str
    risk_score: int
    risk_level: str
    reason: str
    matched_keywords: List[str]



class MultiAgentResponse(BaseModel):
    prompt: str
    session_id: str
    risk_level: Literal["low", "medium", "high", "critical"]
    threat_type: Optional[str] = None
    adjusted_score: int = Field(..., ge=0, le=100)
    internal_risk_score: float = Field(..., ge=0.0, le=1.0)
    verdict: Literal["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    strategy: str
    agents: Dict[str, Any]
    final_response: str
    pipeline_latency_ms: float
    # ANTI-GRAVITY additions
    trust_score: Optional[int] = Field(default=None, ge=0, le=100, description="Session trust score 0–100")
    shadow_mode: bool = Field(default=False, description="True if shadow misdirection is active")
