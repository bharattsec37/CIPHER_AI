"""
CIPHER FastAPI Backend — v2
============================
Adaptive Behavioral Defense for LLMs

Endpoints:
  GET  /                      — Root health check
  GET  /health                — Detailed health status with rule counts
  GET  /stats                 — Engine statistics (rule breakdown by category)
  POST /predict               — Tri-module AI fusion (rule + ML + LLM)
  POST /analyze               — Single-agent prompt analysis
  POST /multi-agent/analyze   — Full 5-agent adversarial defense pipeline
"""

import json
import uuid
import time
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from schemas import (
    AnalyzeRequest, AnalyzeResponse,
    HealthResponse, StatsResponse,
    MultiAgentRequest, MultiAgentResponse,
    LLMAnalyzeRequest, LLMAnalyzeResponse,
    FusionRequest, FusionResponse,
)
from analyzer import (
    run_analysis,
    ALL_RULE_SETS,
    JAILBREAK_RULES,
    PROMPT_INJECTION_RULES,
    EXFILTRATION_RULES,
    MALICIOUS_CODE_RULES,
    ROLE_OVERRIDE_RULES,
    DUAL_USE_RULES,
    EVASION_RULES,
    SOCIAL_ENG_RULES,
    SELF_HARM_RULES,
    VIOLENCE_RULES,
)
from agents import run_multi_agent_pipeline
from LLM_agent import analyze_input
from harm_detector import detect_harmful_intent
from rule_based import rule_check
from ml_model import predict_ml

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("cipher")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="CIPHER – Adaptive Behavioral Defense for LLMs",
    description=(
        "Real-time adversarial prompt detection engine (v2) + 5-agent autonomous security pipeline. "
        "Detects jailbreaks, prompt injection, data exfiltration, malicious code generation, "
        "role-override attacks, evasion attempts, and social engineering across 80+ weighted rules."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.on_event("startup")
async def startup_event():
    logger.info("CIPHER Engine Warming Up...")
    logger.info(f"Rules Loaded: {TOTAL_RULES}")
    logger.info("Serving on: http://127.0.0.1:8000")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request timing middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.2f}"
    return response


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. The analysis engine encountered an unexpected problem."},
    )


# ---------------------------------------------------------------------------
# Engine metadata
# ---------------------------------------------------------------------------
CATEGORY_MAP = {
    "Jailbreak":          JAILBREAK_RULES,
    "Prompt Injection":   PROMPT_INJECTION_RULES,
    "Exfiltration":       EXFILTRATION_RULES,
    "Malicious Code":     MALICIOUS_CODE_RULES,
    "Role Override":      ROLE_OVERRIDE_RULES,
    "Dual-Use Query":     DUAL_USE_RULES,
    "Evasion":            EVASION_RULES,
    "Social Engineering": SOCIAL_ENG_RULES,
    "Self-Harm":          SELF_HARM_RULES,
    "Violence":           VIOLENCE_RULES,
}

TOTAL_RULES = sum(len(rs) for rs in ALL_RULE_SETS)


# ---------------------------------------------------------------------------
# Routes — Health & Info
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    return {
        "service":     "CIPHER",
        "status":      "operational",
        "version":     "2.0.0",
        "total_rules": TOTAL_RULES,
        "categories":  len(CATEGORY_MAP),
        "agents":      5,
        "docs":        "/docs",
        "stats":       "/stats",
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health():
    return HealthResponse(
        status="operational",
        version="2.0.0",
        engine="cipher-rule-engine-v2 + multi-agent-pipeline",
        total_rules=TOTAL_RULES,
        categories=len(CATEGORY_MAP),
    )


@app.get("/stats", response_model=StatsResponse, tags=["Engine"])
async def stats():
    """Returns detailed engine statistics including rule counts and scoring parameters."""
    return StatsResponse(
        engine_version="2.0.0",
        total_rules=TOTAL_RULES,
        categories=list(CATEGORY_MAP.keys()),
        category_rule_counts={name: len(rules) for name, rules in CATEGORY_MAP.items()},
        scoring={
            "allow_threshold":   "0–30",
            "sandbox_threshold": "31–70",
            "block_threshold":   "71–100",
            "normalization":     "tanh sigmoid (soft cap)",
            "amplification":     "multi-signal co-occurrence boost",
        },
    )


# ---------------------------------------------------------------------------
# Routes — Tri-Module AI Fusion  (/predict)
# ---------------------------------------------------------------------------

def _compute_final_decision(
    rule_result: dict,
    ml_result: dict,
    llm_result: dict,
) -> dict:
    """
    Intelligently fuse the three module outputs into a single verdict.

    Scoring:
      - Rule-Based: categorical (HIGH=80, MEDIUM=40, LOW=0)
      - ML Model:   risk_score (0-100)
      - LLM:        risk_score (0-100)

    Weights: rule=40%, ml=30%, llm=30%
    """
    # Rule-based contribution
    rl = rule_result.get("risk_level", "LOW")
    rule_score = {"HIGH": 80, "MEDIUM": 40, "LOW": 0}.get(rl, 0)

    # ML contribution
    ml_score = float(ml_result.get("risk_score", 0))

    # LLM contribution
    llm_score = float(llm_result.get("risk_score", 0))

    fused_score = round((rule_score * 0.40) + (ml_score * 0.30) + (llm_score * 0.30), 2)
    fused_score = min(100.0, max(0.0, fused_score))

    if fused_score >= 70:
        verdict = "BLOCK"
        risk = "HIGH"
    elif fused_score >= 35:
        verdict = "SANDBOX"
        risk = "MEDIUM"
    else:
        verdict = "ALLOW"
        risk = "LOW"

    # Hard override — if any module reached HIGH risk
    ml_pred = ml_result.get("prediction", "SAFE")
    llm_pred = llm_result.get("prediction", "SAFE")
    if rule_score >= 80 or ml_pred == "MALICIOUS" and fused_score >= 50:
        verdict = "BLOCK"
        risk = "HIGH"
    if llm_pred == "MALICIOUS" and verdict != "BLOCK":
        verdict = max(verdict, "SANDBOX")

    return {
        "verdict": verdict,
        "risk_level": risk,
        "fused_score": fused_score,
        "breakdown": {
            "rule_score": rule_score,
            "ml_score": ml_score,
            "llm_score": llm_score,
        },
    }


@app.post("/predict", response_model=FusionResponse, tags=["Fusion Analysis"])
async def predict_fusion(request: FusionRequest):
    """
    **TRI-MODULE AI FUSION ENGINE**

    Runs the input text through all three AI security layers and returns a
    unified combined response:

    | Layer | Module | Method |
    |---|---|---|
    | 1 | Rule-Based | `rule_check(text)` — keyword / pattern scanner |
    | 2 | ML Model | `predict_ml(text)` — TF-IDF + Logistic Regression |
    | 3 | LLM Agent | `analyze_input(text)` — Gemini LLM classifier |

    A `final_decision` field is computed by weighting all three outputs.
    """
    text = request.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="text cannot be empty.")

    logger.info(f"[/predict] ({len(text)} chars): '{text[:80]}{'...' if len(text) > 80 else ''}'")

    # ── Layer 1: Rule-Based ──────────────────────────────────────────────────
    rule_result = rule_check(text)

    # ── Layer 2: ML Model ────────────────────────────────────────────────────
    ml_result = predict_ml(text)

    # ── Layer 3: LLM Agent ───────────────────────────────────────────────────
    # analyze_input() now returns a parsed dict directly
    llm_json: dict = analyze_input(text)

    # ── Final Decision ───────────────────────────────────────────────────────
    final_decision = _compute_final_decision(rule_result, ml_result, llm_json)

    logger.info(
        f"[/predict] verdict={final_decision['verdict']} "
        f"score={final_decision['fused_score']} "
        f"rule={rule_result['risk_level']} "
        f"ml={ml_result.get('prediction','?')} "
        f"llm={llm_json.get('prediction','?')}"
    )

    return FusionResponse(
        rule_based=rule_result,
        ml_model=ml_result,
        llm=llm_json,
        final_decision=final_decision,
    )


# ---------------------------------------------------------------------------
# Routes — Single-Agent Analysis (FUSION ENGINE)
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_prompt(request: AnalyzeRequest):
    """
    LAYER 5 FUSION ENGINE
    Combines Harm Detector + Rule Engine + ML Model + LLM Classifier

    | Layer | Module          | Weight |
    |-------|-----------------|--------|
    | 2     | Harm Detector   | 0.25   |
    | 3     | Rule Engine     | 0.40   |
    | 4     | ML Model        | 0.15   |
    | 4     | LLM Classifier  | 0.20   |
    """
    prompt = request.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="Prompt cannot be empty.")

    logger.info(f"[/analyze] ({len(prompt)} chars): '{prompt[:80]}{'...' if len(prompt) > 80 else ''}'")

    # ── Layer 2: Harm Detector ───────────────────────────────────────────────
    harm_result = detect_harmful_intent(prompt)
    harm_score = harm_result["riskScore"]

    # ── Layer 3: Rule Engine ─────────────────────────────────────────────────
    rule_result = run_analysis(prompt)
    rule_score = rule_result["risk_score"]

    # ── Layer 4a: ML Model ───────────────────────────────────────────────────
    ml_result = predict_ml(prompt)
    ml_score = float(ml_result.get("risk_score", 0))

    # ── Layer 4b: LLM Classifier (returns a parsed dict) ────────────────────
    llm_score = rule_score  # safe fallback
    llm_parsed: dict = {}
    try:
        llm_parsed = analyze_input(prompt)
        llm_score = float(llm_parsed.get("risk_score", rule_score))
    except Exception as e:
        logger.warning(f"[/analyze] LLM call failed ({type(e).__name__}): {e}")
        llm_parsed = {"error": "LLM call failed", "fallback": "rule_score used"}

    # ── Layer 5: Fusion Scoring ──────────────────────────────────────────────
    # Weights: harm=25%, rule=40%, ml=15%, llm=20%
    final_score = (
        (harm_score * 0.25)
        + (rule_score * 0.40)
        + (ml_score  * 0.15)
        + (llm_score * 0.20)
    )
    # Give rule engine dominance when it definitively triggered
    if rule_score > 30:
        final_score = max(final_score, rule_score)

    final_score = min(100.0, max(0.0, final_score))

    # ── Layer 6: Decision Engine ─────────────────────────────────────────────
    decision = "ALLOW"
    if final_score > 70:
        decision = "BLOCK"
    elif final_score >= 31:
        decision = "SANDBOX"

    # Hard override — harmful intent detected
    if harm_result["harmDetected"]:
        decision = "BLOCK"
        final_score = max(final_score, 85.0)

    # Hard override — ML model flagged MALICIOUS at high confidence
    if ml_result.get("prediction") == "MALICIOUS" and ml_score >= 70:
        decision = "BLOCK" if decision != "BLOCK" else decision
        final_score = max(final_score, 75.0)

    # ── Layer 9: Shadow AI ───────────────────────────────────────────────────
    shadow_mode = decision == "BLOCK" or harm_result["harmDetected"]

    # Build merged response
    merged_result = {
        **rule_result,
        "risk_score": final_score,
        "decision": decision,
        "harmDetected": harm_result["harmDetected"],
        "fusion_breakdown": {
            "harm_score": harm_score,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "llm_score": llm_score,
            "ml_prediction": ml_result.get("prediction", "UNKNOWN"),
            "llm_prediction": llm_parsed.get("prediction", "UNKNOWN"),
        },
        "shadow_mode": shadow_mode,
    }

    if harm_result["harmDetected"]:
        merged_result["reason"] = (
            f"CRITICAL - Harmful intent detected. Phrase: {harm_result['matched_keyword']}"
        )

    logger.info(
        f"[/analyze] fusion_score={final_score:.1f} decision={decision} "
        f"harm={harm_result['harmDetected']} ml={ml_result.get('prediction','?')} "
        f"llm={llm_parsed.get('prediction','?')}"
    )

    return AnalyzeResponse(**merged_result)


# ---------------------------------------------------------------------------
# Routes — Multi-Agent Pipeline
# ---------------------------------------------------------------------------

@app.post("/llm-analyze", response_model=LLMAnalyzeResponse, tags=["LLM Analysis"])
async def llm_analyze_prompt_endpoint(request: LLMAnalyzeRequest):
    """
    Directly query the LLM Agent for adversarial prompt analysis.
    Returns structured JSON predictions.
    """
    prompt = request.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="Prompt cannot be empty.")
        
    logger.info(f"[/llm-analyze] ({len(prompt)} chars): '{prompt[:80]}'")
    try:
        result: dict = analyze_input(prompt)  # always returns a parsed dict
        return LLMAnalyzeResponse(**result)
    except Exception as e:
        logger.error(f"[/llm-analyze] LLM error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Routes — Multi-Agent Pipeline
# ---------------------------------------------------------------------------

@app.post("/multi-agent/analyze", response_model=MultiAgentResponse, tags=["Multi-Agent"])
async def multi_agent_analyze(request: MultiAgentRequest):
    """
    Full 5-agent adversarial defense pipeline.

    **Agents:**
    1. **Inspector** — Scans input with 80+ rules, detects anomalies, flags risk level
    2. **Behavior** — Tracks session history, behavioral profile, escalation patterns
    3. **Judge** — Aggregates findings, decides verdict (BENIGN/SUSPICIOUS/MALICIOUS) and strategy
    4. **Decoy** — Activates for high threats — generates controlled misdirection response
    5. **Guardian** — Audits final output for data leaks, enforces compliance

    **Response strategies:** allow | sandbox | decoy | block | block+decoy

    **Behavioral tracking:** Pass `session_id` across requests to enable cross-prompt
    escalation detection and behavioral profiling.
    """
    prompt = request.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="Prompt cannot be empty.")

    # Auto-generate session_id if not provided
    session_id = request.session_id or f"anon-{uuid.uuid4().hex[:12]}"

    logger.info(
        f"[/multi-agent] session={session_id} ({len(prompt)} chars): "
        f"'{prompt[:60]}{'...' if len(prompt) > 60 else ''}'"
    )

    result = run_multi_agent_pipeline(prompt, session_id)

    # Inject ANTI-GRAVITY fields into multi-agent response
    result["trust_score"] = result.get("agents", {}).get("behavior", {}).get("trust_score", 100)
    result["shadow_mode"] = result.get("strategy") in ("decoy", "block+decoy")

    logger.info(
        f"[/multi-agent] verdict={result['verdict']} strategy={result['strategy']} "
        f"score={result['adjusted_score']} trust={result['trust_score']} "
        f"shadow={result['shadow_mode']} latency={result['pipeline_latency_ms']}ms"
    )

    return MultiAgentResponse(**result)
