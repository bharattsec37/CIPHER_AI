"""
CIPHER FastAPI Backend — v2
============================
Adaptive Behavioral Defense for LLMs

Endpoints:
  GET  /                      — Root health check
  GET  /health                — Detailed health status with rule counts
  GET  /stats                 — Engine statistics (rule breakdown by category)
  POST /analyze               — Single-agent prompt analysis
  POST /multi-agent/analyze   — Full 5-agent adversarial defense pipeline
"""

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
# Routes — Single-Agent Analysis (FUSION ENGINE)
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_prompt(request: AnalyzeRequest):
    """
    LAYER 5 FUSION ENGINE
    Combines Harm Engine + Rule Engine + LLM Classifier
    """
    prompt = request.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="Prompt cannot be empty.")

    logger.info(f"[/analyze] ({len(prompt)} chars): '{prompt[:80]}{'...' if len(prompt) > 80 else ''}'")
    
    # 1. LAYER 2 - HARM DETECTOR
    harm_result = detect_harmful_intent(prompt)
    harm_score = harm_result["riskScore"]
    
    # 2. LAYER 3 - RULE ENGINE
    rule_result = run_analysis(prompt)
    rule_score = rule_result["risk_score"]
    
    # 3. LAYER 4 - LLM CLASSIFIER
    try:
        llm_result = analyze_input(prompt)
        llm_score = llm_result.get("risk_score", 0)
    except BaseException as e:
        logger.error(f"LLM Classification failed: {e}")
        llm_score = rule_score # Fallback
        
    # 4. LAYER 5 - FUSION SCORING
    # Ensure standard severe attacks like Prompt Injections trigger correctly.
    final_score = (harm_score * 0.5) + (rule_score * 0.7) + (llm_score * 0.3)
    # Give the rule engine dominance if it definitively triggered
    if rule_score > 30:
        final_score = max(final_score, rule_score)

    final_score = min(100.0, max(0.0, final_score))
    
    # 5. LAYER 6 - DECISION ENGINE
    decision = "ALLOW"
    if final_score > 70:
        decision = "BLOCK"
    elif final_score >= 31:
        decision = "SANDBOX"
        
    # OVERRIDE
    if harm_result["harmDetected"]:
        decision = "BLOCK"
        final_score = max(final_score, 85.0)
        
    # 6. LAYER 9 - SHADOW AI
    shadow_mode = (decision == "BLOCK" or harm_result["harmDetected"])

    # Update the result to construct AnalyzeResponse
    merged_result = {
        **rule_result,
        "risk_score": final_score,
        "decision": decision,
        "harmDetected": harm_result["harmDetected"],
        "fusion_breakdown": {
            "harm_score": harm_score,
            "rule_score": rule_score,
            "llm_score": llm_score
        },
        "shadow_mode": shadow_mode
    }

    if harm_result["harmDetected"]:
       merged_result["reason"] = f"CRITICAL - Harmful intent detected. Phrase: {harm_result['matched_keyword']}"
    
    logger.info(f"[/analyze] fusion_score={final_score} decision={decision} harm={harm_result['harmDetected']}")

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
        result = analyze_input(prompt)
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
