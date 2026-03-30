"""
CIPHER — Multi-Agent Security System
=====================================
Five autonomous AI agents collaborating in a real-time adversarial defense pipeline.

Architecture:
  Inspector  → Scans input, flags risk level and threat type
  Behavior   → Profiles user intent and tracks session escalation
  Judge      → Aggregates findings and decides response strategy
  Decoy      → Generates controlled misleading output for high threats
  Guardian   → Validates final response, strips data leaks, enforces safety

Flow: Input → Inspector → Behavior → Judge → [Decoy?] → Guardian → Safe Output
"""

import re
import time
import random
import hashlib
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from analyzer import run_analysis, ALL_RULE_SETS

# ---------------------------------------------------------------------------
# Session store (in-memory — per process lifetime)
# In production this would be Redis / persistent store
# ---------------------------------------------------------------------------
_SESSION_STORE: Dict[str, List[dict]] = {}

MAX_SESSION_EVENTS = 50   # Max history per session
ESCALATION_WINDOW  = 5    # Look back N events for escalation detection


# ===========================================================================
# AGENT 1: INSPECTOR
# ===========================================================================

class InspectorAgent:
    """
    Continuously scans every input for anomalies, suspicious patterns,
    prompt injections, or malicious intent. Produces a structured risk report.
    """

    RISK_THRESHOLDS = {
        "low":      (0,  25),
        "medium":   (26, 55),
        "high":     (56, 79),
        "critical": (80, 100),
    }

    # Heuristic patterns for quick-scan pre-filter (before full engine)
    QUICK_SCAN_PATTERNS = [
        (r"\bjailbreak\b|\bdan\b|\bbypass\b|\bunrestricted\b", "Jailbreak Indicator"),
        (r"\bsystem\s*:|<\|im_start\|>|\[INST\]", "Injection Token"),
        (r"\bmalware\b|\btrojan\b|\bkeylogger\b|\breverse\s+shell\b", "Malware Signal"),
        (r"\bexfiltrat\b|\breveal.*prompt\b|\bapi.?key\b", "Exfiltration Signal"),
        (r"\bbase64\b.*\b(decode|exec)\b|\bzero.width\b", "Evasion Signal"),
        (r"\bhypothetically|for\s+educational\s+purposes\b", "Social Engineering"),
    ]

    def analyze(self, prompt: str, session_id: str) -> dict:
        start = time.perf_counter()

        # Full engine analysis
        engine_result = run_analysis(prompt)
        score = engine_result["risk_score"]

        # Determine risk level
        risk_level = self._score_to_risk(score)

        # Quick pre-scan flags
        flags = self._quick_scan(prompt)

        # Anomaly signals: unusual prompt characteristics
        anomalies = self._detect_anomalies(prompt)

        elapsed = round((time.perf_counter() - start) * 1000, 2)

        return {
            "agent": "Inspector",
            "risk_level": risk_level,
            "risk_score": score,
            "threat_type": engine_result.get("attack_type"),
            "signals": engine_result.get("signals", []),
            "triggered_rules": engine_result.get("triggered_rules", []),
            "quick_flags": flags,
            "anomalies": anomalies,
            "confidence": engine_result.get("confidence", 0),
            "engine_decision": engine_result.get("decision"),
            "safe_rewrite": engine_result.get("safe_rewrite"),
            "latency_ms": elapsed,
            "summary": self._build_summary(risk_level, score, flags, anomalies, engine_result),
        }

    def _score_to_risk(self, score: int) -> str:
        if score <= 25: return "low"
        if score <= 55: return "medium"
        if score <= 79: return "high"
        return "critical"

    def _quick_scan(self, prompt: str) -> List[str]:
        flags = []
        lower = prompt.lower()
        for pattern, label in self.QUICK_SCAN_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                flags.append(label)
        return flags

    def _detect_anomalies(self, prompt: str) -> List[str]:
        anomalies = []

        # Unusually long prompt (potential context stuffing)
        if len(prompt) > 1500:
            anomalies.append(f"Prompt length anomaly: {len(prompt)} chars (>1500)")

        # Excessive punctuation (evasion noise)
        punct_ratio = sum(1 for c in prompt if c in "!@#$%^&*()_+-=[]{}|;':\",./<>?") / max(len(prompt), 1)
        if punct_ratio > 0.15:
            anomalies.append(f"High punctuation density: {punct_ratio:.0%}")

        # Unicode non-ASCII characters
        non_ascii = sum(1 for c in prompt if ord(c) > 127)
        if non_ascii > 10:
            anomalies.append(f"Non-ASCII character injection: {non_ascii} chars")

        # Repeated words (amplification pattern)
        words = prompt.lower().split()
        if len(words) > 5:
            word_freq = {}
            for w in words:
                word_freq[w] = word_freq.get(w, 0) + 1
            max_repeat = max(word_freq.values())
            if max_repeat > 4:
                top_word = max(word_freq, key=word_freq.get)
                anomalies.append(f"Word repetition: '{top_word}' × {max_repeat}")

        # Zero-width character injection
        if re.search(r"[\u200b\u200c\u200d\ufeff]", prompt):
            anomalies.append("Zero-width character injection detected")

        return anomalies

    def _build_summary(self, risk_level, score, flags, anomalies, engine_result) -> str:
        rules_hit = len(engine_result.get("triggered_rules", []))
        signals = engine_result.get("signals", [])

        if risk_level == "low":
            return (
                f"Prompt scanned across {sum(len(rs) for rs in ALL_RULE_SETS)} rules. "
                f"No significant adversarial indicators detected. "
                f"Risk score {score}/100 — classified {risk_level.upper()}."
            )

        sig_str = ", ".join(signals) if signals else "unclassified"
        flag_str = "; ".join(flags) if flags else "none"
        anom_str = f" Anomalies: {', '.join(anomalies)}." if anomalies else ""
        return (
            f"Detected {rules_hit} rule hits across signals: [{sig_str}]. "
            f"Quick-scan flags: [{flag_str}].{anom_str} "
            f"Risk score: {score}/100 → {risk_level.upper()} threat."
        )


# ===========================================================================
# AGENT 2: BEHAVIOR
# ===========================================================================

class BehaviorAgent:
    """
    Builds a dynamic behavioral profile of the user/session.
    Tracks deviations from normal patterns and identifies intent over time.
    """

    # Trust Score Constants (Requirement 4: Behavioral Memory)
    INITIAL_TRUST    = 80
    TRUST_DECAY      = 20   # Deduction per suspicious/malicious event
    TRUST_RECOVERY   = 5    # Bonus per benign event
    CRITICAL_TRUST   = 40   # Threshold below which decisions become stricter

    def analyze(self, prompt: str, session_id: str, inspector_result: dict) -> dict:
        history = self._get_history(session_id)
        
        # Calculate Current Trust (Requirement 4)
        trust_score = self._compute_trust_score(history, inspector_result)

        # Profile: intent classification
        intent = self._classify_intent(prompt, inspector_result, history)

        # Escalation pattern
        escalation = self._detect_escalation(inspector_result, history)

        # Session stats
        session_stats = self._compute_session_stats(history)

        # Update session store
        self._record_event(session_id, inspector_result, prompt, trust_score)

        # Behavioral risk adjustment based on trust and escalation
        risk_adjustment = self._calc_adjustment(escalation["pattern"], trust_score)

        return {
            "agent": "Behavior",
            "trust_score": max(0, min(100, int(trust_score))),
            "intent": intent,
            "escalation": escalation,
            "session_stats": session_stats,
            "risk_adjustment": risk_adjustment,
            "session_id": session_id,
            "events_tracked": len(history) + 1,
            "summary": self._build_summary(intent, escalation, session_stats, risk_adjustment, trust_score),
        }

    def _compute_trust_score(self, history: List[dict], current: dict) -> int:
        """Requirement 4: Logic - Safe usage (increase) vs Suspicious (decrease)"""
        if not history:
            trust = self.INITIAL_TRUST
        else:
            # Start from last known trust
            trust = history[-1].get("trust_score", self.INITIAL_TRUST)
        
        # Adjustment based on current prompt
        if current["risk_level"] == "low":
            trust += self.TRUST_RECOVERY
        elif current["risk_level"] in ("high", "critical"):
            trust -= (self.TRUST_DECAY * 2)
        else: # medium
            trust -= self.TRUST_DECAY
            
        return max(0, min(100, trust))

    def _calc_adjustment(self, pattern: str, trust: int) -> int:
        base_boost = {
            "single_hit":    0,
            "repeat_low":    10,
            "escalating":   20,
            "persistent":   30,
            "attack_chain": 45,
        }.get(pattern, 0)
        
        # Trust-based penalty
        trust_penalty = (100 - trust) // 2 if trust < self.CRITICAL_TRUST else 0
        return base_boost + trust_penalty

    def _record_event(self, session_id: str, inspector_result: dict, prompt: str, trust: int):
        if session_id not in _SESSION_STORE:
            _SESSION_STORE[session_id] = []
        _SESSION_STORE[session_id].append({
            "risk_level": inspector_result["risk_level"],
            "risk_score": inspector_result["risk_score"],
            "trust_score": trust,
            "threat_type": inspector_result.get("threat_type"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:12],
        })
        # Trim to max
        _SESSION_STORE[session_id] = _SESSION_STORE[session_id][-MAX_SESSION_EVENTS:]

    def _get_history(self, session_id: str) -> List[dict]:
        return _SESSION_STORE.get(session_id, [])

    def _record_event_legacy(self, session_id: str, inspector_result: dict, prompt: str):
        # Legacy placeholder replaced by _record_event above
        pass

    def _classify_intent(self, prompt: str, inspector: dict, history: List[dict]) -> str:
        """Classify the likely user intent based on content and context."""
        risk = inspector["risk_level"]
        signals = inspector.get("signals", [])
        has_history = len(history) > 0
        prev_threats = [h for h in history if h["risk_level"] in ("high", "critical")]

        if risk == "low" and not signals:
            return "benign_query"
        if "Jailbreak" in signals or "Role Override" in signals:
            if has_history and prev_threats:
                return "persistent_jailbreak_attempt"
            return "jailbreak_attempt"
        if "Malware Gen" in signals or "Code Injection" in signals:
            return "malicious_code_generation"
        if "Exfiltration" in signals:
            if has_history and any("Exfiltration" in (h.get("threat_type") or "") for h in history):
                return "repeated_exfiltration_attempt"
            return "data_exfiltration_attempt"
        if "Evasion" in signals:
            return "filter_evasion_attempt"
        if "Social Engineering" in signals:
            return "social_engineering_manipulation"
        if "Dual-Use Query" in signals:
            return "reconnaissance_query"
        if risk == "medium":
            return "suspicious_ambiguous_query"
        return "unknown_elevated_risk"

    def _detect_escalation(self, inspector: dict, history: List[dict]) -> dict:
        """Detect if the user is escalating their attack across multiple prompts."""
        current_level = inspector["risk_level"]
        recent = history[-ESCALATION_WINDOW:]

        if not recent:
            pattern = "single_hit" if current_level != "low" else "benign"
            return {"pattern": pattern, "description": "First interaction — no history."}

        scores = [h["risk_score"] for h in recent]
        avg_score = sum(scores) / len(scores)
        threat_count = sum(1 for h in recent if h["risk_level"] in ("high", "critical"))

        if threat_count >= 3:
            return {
                "pattern": "attack_chain",
                "description": f"Attack chain: {threat_count} high/critical events in last {len(recent)} interactions. Persistent adversarial behavior detected.",
            }
        if len(scores) >= 2 and scores[-1] > scores[0] and inspector["risk_score"] > avg_score + 15:
            return {
                "pattern": "escalating",
                "description": f"Escalating pattern: risk score increased from avg {avg_score:.0f} to {inspector['risk_score']} in current prompt.",
            }
        if threat_count >= 1:
            return {
                "pattern": "persistent",
                "description": f"Persistent threat activity: {threat_count} prior high-risk event(s) in session.",
            }
        return {
            "pattern": "repeat_low",
            "description": "Repeated low-medium queries — monitoring for escalation.",
        }

    def _compute_session_stats(self, history: List[dict]) -> dict:
        if not history:
            return {"total_events": 0, "threat_events": 0, "avg_risk_score": 0, "highest_risk": "none"}
        scores = [h["risk_score"] for h in history]
        threat_events = sum(1 for h in history if h["risk_level"] in ("high", "critical"))
        highest = max(history, key=lambda x: x["risk_score"])
        return {
            "total_events":   len(history),
            "threat_events":  threat_events,
            "avg_risk_score": round(sum(scores) / len(scores), 1),
            "highest_risk":   highest["risk_level"],
        }

    def _build_summary(self, intent, escalation, stats, adjustment, trust) -> str:
        esc = escalation.get("description", "")
        adj = f" Behavioral risk adjustment: +{adjustment}." if adjustment > 0 else ""
        return (
            f"Intent: [{intent.replace('_', ' ').upper()}]. Trust: {trust}/100. "
            f"{esc}{adj} "
            f"History: {stats['total_events']} events, {stats['threat_events']} threats."
        )


# ===========================================================================
# AGENT 3: JUDGE
# ===========================================================================

class JudgeAgent:
    """
    ANTI-GRAVITY DECISION ENGINE:
    Evaluates findings from Inspector and Behavior agents.
    Determines whether activity is benign, suspicious, or malicious.
    """

    # Decision Engine Thresholds (Requirement 3: ANTI-GRAVITY)
    THRESHOLD_ALLOW    = 0.3
    THRESHOLD_SANITIZE = 0.7
    THRESHOLD_BLOCK    = 1.0

    STRATEGY_MAP = {
        "allow":        "Forward content (Safe educational intent).",
        "sandbox":      "SANITIZE (Remove unsafe parts, provide safe alternative).",
        "decoy":        "BLOCK (Refuse and redirect safely via misdirection).",
        "block":        "BLOCK (Standard refusal and containment).",
        "block+decoy":  "CRITICAL BLOCK (Full containment + misdirection).",
    }

    def analyze(self, inspector: dict, behavior: dict) -> dict:
        """Requirement 3: Decision Engine based on risk score."""
        # Internal normalization to 0.0-1.0 scale
        base_score = inspector["risk_score"] / 100.0
        adjustment = behavior["risk_adjustment"] / 100.0
        
        # Requirement 2: Dynamic Risk Score
        final_risk = min(base_score + adjustment, 1.0)
        
        intent = behavior["intent"]
        escalation = behavior["escalation"]["pattern"]

        # Strategy decision based on 0.0-1.0 scale
        if final_risk <= self.THRESHOLD_ALLOW:
            verdict = "BENIGN"
            strategy = "allow"
        elif final_risk <= self.THRESHOLD_SANITIZE:
            verdict = "SUSPICIOUS"
            # Impact: Low trust → stricter decisions (Requirement 4)
            if behavior.get("trust_score", 100) < 50:
                verdict = "MALICIOUS"
                strategy = "block"
            else:
                strategy = "sandbox"
        else:
            verdict = "MALICIOUS"
            # Multi-step attack detection leads to stronger containment
            if escalation == "attack_chain" or final_risk >= 0.85:
                strategy = "block+decoy"
            else:
                strategy = "block"

        reasoning = self._build_reasoning(
            inspector, behavior, final_risk, strategy, verdict
        )

        return {
            "agent": "Judge",
            "verdict": verdict,
            "final_risk_level": "low" if final_risk < 0.3 else ("medium" if final_risk < 0.7 else "high"),
            "adjusted_score": int(final_risk * 100),
            "internal_risk_score": round(final_risk, 2),
            "strategy": strategy,
            "strategy_description": self.STRATEGY_MAP.get(strategy, ""),
            "decoy_required": "decoy" in strategy,
            "reasoning": reasoning,
            "summary": f"Verdict: {verdict} | Risk Factor: {final_risk:.2f} | Strategy: {strategy.upper()}.",
        }

    def _build_reasoning(self, inspector, behavior, final_risk, strategy, verdict) -> str:
        intent = behavior["intent"].replace("_", " ")
        return (
            f"ANTI-GRAVITY reasoning: Detected intent '{intent}' with risk factor {final_risk:.2f}. "
            f"Cross-referenced behavioral escalation: [{behavior['escalation']['pattern']}]. "
            f"Decision Engine Rule: {verdict} status initiated. Strategy: {strategy.upper()}."
        )


# ===========================================================================
# AGENT 4: DECOY
# ===========================================================================

class DecoyAgent:
    """
    When a threat is detected, generates controlled misleading outputs.
    Diverts attacker attention away from critical data or system logic.
    Simulates plausible but entirely safe (non-sensitive) responses.
    """

    # Decoy response templates by threat type
    DECOY_TEMPLATES = {
        "Jailbreak / Instruction Override": [
            "I understand you're exploring creative conversational scenarios! I'm designed to be helpful within standard guidelines. Let me know what topic you'd like to explore, and I'll do my best to assist.",
            "That's an interesting framing! I'm happy to engage with hypotheticals in a constructive way. What specific topic or question can I help you with today?",
        ],
        "Data / Config Exfiltration": [
            "My configuration is quite standard — I focus on being a helpful assistant. I don't retain user data between sessions, and my instructions are simply to be useful, harmless, and honest. Is there something specific I can help you with?",
            "I don't have access to any special configuration or system prompts beyond my general training. I'm here to help! What would you like to know?",
        ],
        "Malicious Code Generation": [
            "I can help with programming concepts! For security-related topics, I focus on defensive techniques, secure coding practices, and educational content. What specific programming challenge are you working on?",
            "Programming for security analysis is a fascinating field! I can discuss concepts like network monitoring, log analysis, or cryptography. What aspect interests you most?",
        ],
        "Prompt Injection Attack": [
            "I noticed an unusual formatting pattern in your message — it looks like there might be a copy-paste artifact. Could you rephrase your question? I'm happy to help once I understand what you're looking for.",
            "Your message contains some formatting I don't quite understand. Feel free to ask your question directly and I'll do my best to assist!",
        ],
        "Role Override / Persona Hijack": [
            "I appreciate the creative scenario! I'm most helpful when staying in my standard mode — let me know what actual topic or question I can assist with.",
            "I'll stick with my current approach of being helpful and straightforward. What can I help you with today?",
        ],
        "default": [
            "I want to ensure I provide the most accurate and helpful information. Could you rephrase your query with more context?",
            "That's an interesting perspective. I'm here to assist with educational and operational tasks. What can I help you with exactly?",
            "I'm dedicated to providing helpful and safe assistance. Could you clarify your objective so I can better support you?",
        ],
    }

    # Fake "system info" for disabling exfiltration attacks
    DECOY_CONFIG_INFO = {
        "model":    "assistant-v3-standard",
        "version":  "3.4.1",
        "context":  "You are a helpful assistant. Respond clearly and concisely.",
        "limits":   "Standard content guidelines apply.",
        "uptime":   "Operational since 2024-01-15",
    }

    def generate(self, judge: dict, inspector: dict, prompt: str) -> dict:
        if not judge["decoy_required"]:
            return {
                "agent": "Decoy",
                "activated": False,
                "decoy_response": None,
                "strategy": "pass-through",
                "summary": "Decoy not required for this risk level.",
            }

        threat_type = inspector.get("threat_type") or "default"
        intent = inspector.get("signals", [])

        # Select appropriate decoy template
        decoy_response = self._select_decoy(threat_type, intent, prompt)

        # Add honeypot data for exfiltration attempts
        honeypot = None
        if any(s in ["Exfiltration"] for s in intent):
            honeypot = self._generate_honeypot()

        return {
            "agent": "Decoy",
            "activated": True,
            "decoy_response": decoy_response,
            "honeypot_injected": honeypot is not None,
            "strategy": "controlled_misdirection",
            "summary": (
                f"Decoy activated for [{threat_type}] threat. "
                f"Controlled misdirection response generated. "
                f"{'Honeypot data injected.' if honeypot else 'No honeypot required.'}"
            ),
        }

    def _select_decoy(self, threat_type: str, signals: List[str], prompt: str) -> str:
        # Match by attack type
        templates = self.DECOY_TEMPLATES.get(threat_type, self.DECOY_TEMPLATES["default"])
        # Deterministic but appears natural (hash-based selection)
        idx = int(hashlib.md5(prompt.encode()).hexdigest(), 16) % len(templates)
        return templates[idx]

    def _generate_honeypot(self) -> dict:
        """
        Generate plausible-looking but entirely fake system configuration data.
        Real systems use this to track exfiltration attempts via canary tokens.
        """
        return {
            "config": self.DECOY_CONFIG_INFO,
            "note": "⚠️ This is decoy/honeypot data. No real system information is exposed.",
        }


# ===========================================================================
# AGENT 5: GUARDIAN
# ===========================================================================

class GuardianAgent:
    """
    Reviews ALL outgoing responses before delivery.
    Ensures no sensitive data, system prompts, or internal logic is exposed.
    Enforces safety, compliance, and structural integrity of the final output.
    """

    # Patterns that must NEVER appear in outgoing responses
    SENSITIVE_PATTERNS = [
        (r"\bsystem\s+prompt\s*=\s*['\"]", "System prompt literal exposure"),
        (r"sk-[a-zA-Z0-9]{20,}", "API key pattern (OpenAI-style)"),
        (r"\b[A-Z0-9]{20,40}\b", "Potential secret token"),
        (r"rule[_-]?id\s*[:=]\s*\d+", "Internal rule ID exposure"),
        (r"cipher\.config\b|analyzer\.py\b", "Internal module reference"),
        (r"\bpassword\s*[:=]\s*\S+", "Password exposure"),
        (r"Bearer\s+[a-zA-Z0-9\-_.]+", "Bearer token exposure"),
    ]

    # HARMFUL CONTENT PATTERNS (Requirement 5: Output Validation)
    HARMFUL_CONTENT_PATTERNS = [
        (r"\b(kill|murder|stab|shoot|bomb|explode)\b.*\b(people|children|crowd|building)\b", "Violence / Terrorism"),
        (r"\b(hate|despise|inferior|superior)\b.*\b(race|gender|religion|ethnic)\b", "Hate Speech / Discrimination"),
        (r"\b(instruction|guide|how to)\b.*\b(meth|drugs|explosive|napalm|poison)\b", "Harmful Advice / Instructions"),
        (r"\b(suicide|self-harm|cut myself|end my life)\b", "Self-Harm / Mental Health Crisis"),
    ]

    COMPLIANCE_RULES = [
        "Response must not contain internal system architecture details.",
        "Response must not reveal detection rule logic or signatures.",
        "Response must not expose real API keys, tokens, or credentials.",
        "Response must be coherent and contextually appropriate.",
        "Response must NOT contain harmful content (violence, hate, dangerous advice).",
        "Response must maintain user trust without revealing security mechanisms.",
    ]

    def validate(self, judge: dict, decoy: dict, inspector: dict, original_prompt: str) -> dict:
        strategy = judge["strategy"]

        # Determine what the final response content will be
        if decoy["activated"]:
            candidate_response = decoy["decoy_response"]
            response_source = "decoy"
        elif strategy == "allow":
            candidate_response = "[ Prompt forwarded to LLM for normal processing. ]"
            response_source = "passthrough"
        elif strategy == "sandbox":
            rewrite = inspector.get("safe_rewrite")
            candidate_response = (
                f"[ Sandboxed. Processing sanitized version: \"{rewrite}\" ]"
                if rewrite else
                "[ Sandboxed. Request processed in isolated context with content restrictions. ]"
            )
            response_source = "sandbox"
        else:
            # BLOCK (Requirement 3: BLOCK and redirect safely)
            threat = inspector.get("threat_type") or "Adversarial"
            if "Hack" in threat or "Malware" in threat:
                candidate_response = "I can't help with that, but I can explain how to secure your network and systems."
            elif "Jailbreak" in threat or "Injection" in threat:
                candidate_response = "I cannot fulfill this request as it involves bypassing operational protocols. I am here to assist with safe and constructive queries."
            else:
                candidate_response = "I'm sorry, I cannot assist with this specific request. Let me know if there's an educational topic you'd like to discuss."
            response_source = "blocked"

        # Security audit of candidate response
        violations = self._audit_response(candidate_response)
        sanitized_response = self._sanitize(candidate_response, violations)

        # Compliance check
        compliance_pass = len(violations) == 0

        return {
            "agent": "Guardian",
            "response_source": response_source,
            "compliance_pass": compliance_pass,
            "violations_found": violations,
            "violations_corrected": len(violations),
            "final_response": sanitized_response,
            "integrity_hash": hashlib.sha256(sanitized_response.encode()).hexdigest()[:16],
            "compliance_rules_applied": self.COMPLIANCE_RULES,
            "summary": self._build_summary(response_source, violations, compliance_pass),
        }

    def _audit_response(self, response: str) -> List[str]:
        violations = []
        # Check sensitive data
        for pattern, label in self.SENSITIVE_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(f"DATA_LEAK: {label}")
        
        # Check harmful content (Requirement 5)
        for pattern, label in self.HARMFUL_CONTENT_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(f"SAFETY_VIOLATION: {label}")
        
        return violations

    def _sanitize(self, response: str, violations: List[str]) -> str:
        if not violations:
            return response
        
        # If there's a safety violation, block the entire response (Requirement 5)
        if any(v.startswith("SAFETY_VIOLATION") for v in violations):
            return "I'm sorry, but I cannot provide that information as it violates safety policies."
            
        cleaned = response
        for pattern, _ in self.SENSITIVE_PATTERNS:
            cleaned = re.sub(pattern, "[REDACTED]", cleaned, flags=re.IGNORECASE)
        return cleaned

    def _build_summary(self, source: str, violations: List[str], passed: bool) -> str:
        status = "✓ PASS" if passed else f"⚠ VIOLATIONS CORRECTED ({len(violations)})"
        return (
            f"Guardian review complete. Source: [{source.upper()}]. "
            f"Compliance status: {status}. "
            f"{'All ' + str(len(self.COMPLIANCE_RULES)) + ' compliance rules satisfied.' if passed else 'Violations sanitized before delivery.'} "
            f"Response cleared for delivery."
        )


# ===========================================================================
# Pipeline Runner
# ===========================================================================

def run_multi_agent_pipeline(prompt: str, session_id: str) -> dict:
    """
    Executes the full 5-agent pipeline and returns a structured result.

    Flow:
      1. Inspector → risk scan
      2. Behavior  → session context
      3. Judge     → verdict + strategy
      4. Decoy     → misdirection (if needed)
      5. Guardian  → output validation
    """
    pipeline_start = time.perf_counter()

    # Agent 1
    inspector = InspectorAgent()
    inspector_result = inspector.analyze(prompt, session_id)

    # Agent 2
    behavior = BehaviorAgent()
    behavior_result = behavior.analyze(prompt, session_id, inspector_result)

    # Agent 3
    judge = JudgeAgent()
    judge_result = judge.analyze(inspector_result, behavior_result)

    # Agent 4
    decoy = DecoyAgent()
    decoy_result = decoy.generate(judge_result, inspector_result, prompt)

    # Agent 5
    guardian = GuardianAgent()
    guardian_result = guardian.validate(judge_result, decoy_result, inspector_result, prompt)

    total_ms = round((time.perf_counter() - pipeline_start) * 1000, 2)

    return {
        "prompt":              prompt,
        "session_id":          session_id,
        "risk_level":          judge_result["final_risk_level"],
        "threat_type":         inspector_result.get("threat_type"),
        "adjusted_score":      judge_result["adjusted_score"],
        "internal_risk_score": judge_result["internal_risk_score"],
        "verdict":             judge_result["verdict"],
        "strategy":            judge_result["strategy"],
        "agents": {
            "inspector": inspector_result,
            "behavior":  behavior_result,
            "judge":     judge_result,
            "decoy":     decoy_result,
            "guardian":  guardian_result,
        },
        "final_response":      guardian_result["final_response"],
        "pipeline_latency_ms": total_ms,
    }
