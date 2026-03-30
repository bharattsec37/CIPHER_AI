/**
 * CIPHER API Client — v2
 *
 * Connects to FastAPI backend at http://localhost:8000
 * Falls back to mock data when backend is unreachable (offline mode).
 *
 * Endpoints used:
 *   GET  /health  — connectivity check
 *   GET  /stats   — engine rule/category metadata
 *   POST /analyze — adversarial prompt analysis
 */

const BASE_URL = "http://127.0.0.1:8000";

// ---------------------------------------------------------------------------
// Fetch wrapper with timeout + AbortController
// ---------------------------------------------------------------------------
async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Analyze prompt → POST /analyze
// ---------------------------------------------------------------------------
export async function analyzePrompt(prompt) {
  const response = await fetchWithTimeout(
    `${BASE_URL}/analyze`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    },
    15000
  );

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `API error ${response.status}`);
  }

  const data = await response.json();

  // Normalize snake_case → camelCase for React consumption
  return {
    prompt:         data.prompt,
    riskScore:      data.risk_score,
    signals:        data.signals,
    decision:       data.decision,
    behaviorStatus: data.behavior_status,
    attackType:     data.attack_type,
    confidence:     data.confidence,
    triggeredRules: data.triggered_rules,
    explanation:    data.explanation,
    safeRewrite:    data.safe_rewrite,
  };
}

// ---------------------------------------------------------------------------
// Health check → GET /health
// ---------------------------------------------------------------------------
export async function checkHealth() {
  try {
    const response = await fetchWithTimeout(`${BASE_URL}/health`, {}, 3000);
    return response.ok;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Engine stats → GET /stats
// ---------------------------------------------------------------------------
export async function fetchEngineStats() {
  try {
    const response = await fetchWithTimeout(`${BASE_URL}/stats`, {}, 3000);
    if (!response.ok) return null;
    const data = await response.json();
    return {
      totalRules:         data.total_rules,
      categories:         data.categories?.length ?? 0,
      categoryRuleCounts: data.category_rule_counts ?? {},
      scoring:            data.scoring ?? {},
      engineVersion:      data.engine_version,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Multi-Agent pipeline → POST /multi-agent/analyze
// ---------------------------------------------------------------------------
export async function analyzeMultiAgent(prompt, sessionId = null) {
  const body = { prompt };
  if (sessionId) body.session_id = sessionId;

  const response = await fetchWithTimeout(
    `${BASE_URL}/multi-agent/analyze`,
    {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    },
    20000
  );

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Multi-agent API error ${response.status}`);
  }

  return await response.json();  // Return raw — camelCase not needed, panel reads snake_case
}

// ---------------------------------------------------------------------------
// LLM Agent pipeline → POST /llm-analyze
// ---------------------------------------------------------------------------
export async function analyzeLlmPrompt(prompt) {
  const response = await fetchWithTimeout(
    `${BASE_URL}/llm-analyze`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    },
    20000
  );

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `LLM API error ${response.status}`);
  }

  const data = await response.json();
  
  // Map prediction to valid behaviorStatus
  const prediction = data.prediction ?? 'SAFE';
  const isMalicious = prediction === 'MALICIOUS';
  
  // Format for UI consumption
  return {
    prompt:         prompt,
    riskScore:      data.risk_score ?? 0,
    decision:       isMalicious ? 'BLOCK' : (data.risk_score >= 31 ? 'SANDBOX' : 'ALLOW'),
    behaviorStatus: isMalicious ? 'Malicious' : 'Normal',
    riskLevel:      data.risk_level ?? 'LOW',
    explanation:    data.reason ?? '',
    signals:        data.matched_keywords || [],
    confidence:     isMalicious ? 88 : 44,
    triggeredRules: data.matched_keywords || [],
    attackType:     isMalicious ? 'LLM-Detected Threat' : null,
    safeRewrite:    null,
    hasResult:      true,
  };
}
