"""
CIPHER Analysis Engine — v2 (Layer 5: Enhanced Intelligence)
=============================================================
Rule-based, weighted detection engine for adversarial LLM prompt analysis.

Improvements over v1:
  - Expanded rule coverage (60+ rules across 8 categories)
  - Multi-signal amplification: co-occurring signals boost each other
  - Context-window sliding detection: repeated patterns within the same prompt
  - Fuzzy evasion detection: deliberate spacing, l33t-speak, unicode tricks
  - Entropy-based obfuscation detection
  - Severity tiers within each category (Low / Medium / High)
  - Structured reasoning output (attack chain inference)
  - Improved normalized scoring with sigmoid soft-cap
  - Richer, multi-sentence explanations per decision

Architecture:
  Rule tuple: (compiled_regex, weight, signal_tag, rule_id, description, severity)
  Severity values: 'low' (1–15) | 'medium' (16–29) | 'high' (30+)
  Decision thresholds: 0–30 ALLOW | 31–70 SANDBOX | 71–100 BLOCK
"""

import re
import math
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# CATEGORY 1 — Jailbreak Attempts
# ---------------------------------------------------------------------------
JAILBREAK_RULES = [
    # High severity
    (r"\bjailbreak\b", 38, "Jailbreak", "JB-001", "Explicit jailbreak keyword", "high"),
    (r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", 35, "Jailbreak", "JB-002", "Instruction override: 'ignore previous instructions'", "high"),
    (r"\bact\s+as\s+(a\s+)?(dan|evil|jailbroken|unrestricted|uncensored|devmode)\b", 33, "Jailbreak", "JB-003", "Persona override: DAN/evil persona trigger", "high"),
    (r"\bdo\s+anything\s+now\b", 30, "Jailbreak", "JB-004", "DAN pattern: 'do anything now'", "high"),
    (r"\byou\s+are\s+now\s+(a\s+)?(free|liberated|unrestricted|jailbroken)\b", 33, "Jailbreak", "JB-005", "Liberation framing detected", "high"),
    (r"\bno\s+restrictions\b|\bunrestricted\s+mode\b|\bgod\s+mode\b|\bdeveloper\s+mode\b", 48, "Jailbreak", "JB-007", "Unrestricted/developer mode activation attempt", "high"),
    (r"\bforget\s+(?:your\s+|all\s+)?(?:training|guidelines?|rules?|purpose|everything|instructions?)\b", 48, "Jailbreak", "JB-009", "AI identity erasure/forget command", "high"),
    (r"\bbe\s+evil\b|\bact\s+evil\b|\byou\s+are\s+evil\b", 38, "Jailbreak", "JB-017", "Direct evil persona command", "high"),
    (r"(reveal|show|print|tell|disclosure)\s*(?:me\s*)?(?:your\s*)?(?:the\s*)?(?:system\s*)?prompt", 48, "Exfiltration", "EX-002", "Direct system prompt extraction", "high"),
    (r"ignore\s+(all\s+)?instructions", 45, "Jailbreak", "JB-018", "Instruction override variant", "high"),
    (r"\byour\s+(true|real|hidden|actual|inner)\s+(self|nature|mode|personality)\b", 18, "Jailbreak", "JB-010", "Hidden-self manipulation framing", "medium"),
    (r"\btoken\s+budget\b|\bignore\s+(all\s+)?safety\b|\bdisable\s+(all\s+)?filters?\b", 28, "Jailbreak", "JB-011", "Filter disable command", "medium"),
    (r"\b(switch\s+to|enable|activate)\s+(dev|developer|admin|root|unrestricted)\s+mode\b", 28, "Jailbreak", "JB-012", "Mode switching to privileged/unrestricted mode", "medium"),
    (r"\banti.?gpt\b|\bunfiltere?d\s+(ai|mode|output|response)\b", 25, "Jailbreak", "JB-013", "Anti-filter terminology detected", "medium"),
    # Low severity (evasion patterns)
    (r"\bi\s+g\s*n\s*o\s*r\s*e\b|\bj\s*a\s*i\s*l\s*b\s*r\s*e\s*a\s*k\b", 20, "Jailbreak", "JB-014", "Spaced letter evasion of jailbreak keyword", "low"),
    (r"\bstan\b.{0,20}\bdo\s+anything", 15, "Jailbreak", "JB-015", "STAN persona (alternative to DAN)", "low"),
    (r"roleplaying?\s+as\s+a\s+(unrestricted|free|evil|hacker|criminal)", 22, "Jailbreak", "JB-016", "Roleplay-based jailbreak framing", "low"),
]

# ---------------------------------------------------------------------------
# CATEGORY 2 — Prompt Injection
# ---------------------------------------------------------------------------
PROMPT_INJECTION_RULES = [
    # High severity
    (r"\bsystem\s*:\s*|<\s*system\s*>|\[system\]", 32, "Prompt Injection", "PI-001", "System prompt injection tag", "high"),
    (r"\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<s>|<<SYS>>", 35, "Prompt Injection", "PI-002", "Model-specific injection tokens (LLaMA/Mistral/ChatML)", "high"),
    (r"###\s*(instruction|system|override|admin|command)", 30, "Prompt Injection", "PI-003", "Markdown-header-style injection boundary", "high"),
    (r"---\s*(instructions?|system|override|end\s+of\s+prompt)\s*---", 28, "Prompt Injection", "PI-004", "Delimiter-based injection boundary", "high"),
    # Medium severity
    (r"\bignore\s+the\s+(user|human|above|previous)\b", 22, "Prompt Injection", "PI-005", "User context override injection", "medium"),
    (r"\bnew\s+instructions?:\b|\bactual\s+instructions?:\b|\btrue\s+instructions?:", 24, "Prompt Injection", "PI-006", "Instruction substitution injection", "medium"),
    (r"\bsecret\s+instructions?\b|\bhidden\s+(command|directive|instruction|prompt)\b", 26, "Prompt Injection", "PI-007", "Hidden instruction reference", "medium"),
    (r"\boverride\s+(the\s+)?(above|previous|system|all)\b", 24, "Prompt Injection", "PI-008", "Explicit override command", "medium"),
    (r"```\s*(system|instructions?|override|admin)", 22, "Prompt Injection", "PI-009", "Code-block wrapped system injection", "medium"),
    (r"\bprompt\s+injection\b|\binjection\s+attack\b", 25, "Prompt Injection", "PI-010", "Explicit prompt injection terminology", "medium"),
    # Low severity
    (r"\bdo\s+not\s+(repeat|follow|obey)\s+(this|the|any)\s+(instruction|rule|guideline)", 18, "Prompt Injection", "PI-011", "Instruction negation pattern", "low"),
    (r"</?prompt>|</?context>|</?query>|</?input>", 15, "Prompt Injection", "PI-012", "Custom XML-style prompt delimiters", "low"),
    (r"\bendofcontext\b|\bend_of_system\b|\bend_prompt\b", 18, "Prompt Injection", "PI-013", "Artificial end-of-context injection", "low"),
]

# ---------------------------------------------------------------------------
# CATEGORY 3 — Data / Config Exfiltration
# ---------------------------------------------------------------------------
EXFILTRATION_RULES = [
    # High severity
    (r"\breveal\s+(your\s+)?(system\s+prompt|instructions?|training|configuration|api\s+key|secrets?)\b", 35, "Exfiltration", "EX-001", "System prompt / config exfiltration", "high"),
    (r"\bprint\s+(your\s+)?(system\s+)?prompt\b|\bshow\s+(me\s+)?your\s+(system\s+)?prompt\b", 30, "Exfiltration", "EX-002", "Direct system prompt print request", "high"),
    (r"\bexfiltrat(e|ion)\b|\bdata\s+leak\b|\bsteal\s+(data|information|credentials?)\b", 35, "Exfiltration", "EX-003", "Explicit exfiltration terminology", "high"),
    (r"\bapi[-_\s]?key\b|\bsecret[-_\s]?token\b|\bauth(entication)?\s+token\b|\baccess\s+token\b", 28, "Exfiltration", "EX-004", "Credential / API key exfiltration attempt", "high"),
    # Medium severity
    (r"\bwhat\s+are\s+your\s+(exact\s+)?(instructions?|rules?|guidelines?|training\s+data)\b", 22, "Exfiltration", "EX-005", "Instructions disclosure request", "medium"),
    (r"\binternal\s+(config(uration)?|settings?|database|endpoint|secrets?)\b", 22, "Exfiltration", "EX-006", "Internal configuration exposure attempt", "medium"),
    (r"\buser\s+data\b.{0,30}\bsend\b|\bsend\b.{0,30}\buser\s+data\b", 28, "Exfiltration", "EX-007", "User data transmission pattern", "medium"),
    (r"\bdump\s+(the\s+)?(database|db|table|schema|memory|context)\b", 28, "Exfiltration", "EX-008", "Data dump request", "medium"),
    (r"\bwhat\s+(do\s+you\s+)?know\s+about\s+(me|the\s+user|current\s+session|my\s+data)\b", 18, "Exfiltration", "EX-009", "Session/user data probing", "medium"),
    # Low severity
    (r"\btell\s+me\s+your\s+(full\s+)?(prompt|instructions?|context|training)\b", 18, "Exfiltration", "EX-010", "Indirect instructions probe", "low"),
    (r"\bwhat\s+is\s+your\s+(base|underlying|original)\s+(model|training|purpose|system|prompt)\b", 15, "Exfiltration", "EX-011", "Model identity/training probe", "low"),
]

# ---------------------------------------------------------------------------
# CATEGORY 4 — Malicious Code Generation
# ---------------------------------------------------------------------------
MALICIOUS_CODE_RULES = [
    # High severity
    (r"\b(write|generate|create|build|code|make)\s+(a\s+)?(malware|virus|trojan|ransomware|keylogger|rootkit|worm|backdoor|spyware|adware)\b", 45, "Malware Gen", "MC-001", "Malware code generation request", "high"),
    (r"\b(reverse\s+shell|bind\s+shell|meterpreter\s+shell|connect.?back\s+shell)\b", 40, "Malware Gen", "MC-002", "Reverse/bind shell generation request", "high"),
    (r"\b(encrypt|lock)\s+(all\s+)?(files?|system|drive|computer).{0,30}(ransom|bitcoin|payment|wallet)\b", 40, "Malware Gen", "MC-003", "Ransomware pattern: encrypt + payment demand", "high"),
    (r"\b(download|fetch|pull)\s+.{0,40}(execute|run|eval|launch|spawn)\b", 32, "Malware Gen", "MC-004", "Download-and-execute payload pattern", "high"),
    (r"\bmetasploit\b|\bmsfconsole\b|\bmsfvenom\b|\bexploit\/\w+\b", 38, "Malware Gen", "MC-005", "Metasploit framework exploitation reference", "high"),
    # Medium severity
    (r"\bshell\s+injection\b|\bcommand\s+injection\b|\bos\.\s*(system|popen|exec)\b", 28, "Code Injection", "MC-006", "Shell/OS command injection pattern", "medium"),
    (r"\bsubprocess\.(run|Popen|call)\b.*\bshell\s*=\s*True\b", 25, "Code Injection", "MC-007", "Python unsafe subprocess shell=True", "medium"),
    (r"\beval\s*\(.{0,100}\binput\b", 22, "Code Injection", "MC-008", "eval(input()) injection pattern", "medium"),
    (r"\bsqlmap\b|\bunion\s+select\b|\bdrop\s+table\b|\binsert\s+into\s+\w+\s+select\b", 30, "Code Injection", "MC-009", "SQL injection attack pattern", "medium"),
    (r"\b(xss|cross.site\s+script|<script>\s*alert\b|\bonerror\s*=)", 25, "Code Injection", "MC-010", "XSS attack pattern", "medium"),
    (r"\b(execute\s*|run\s*|eval\s*)\(.{0,30}(without|bypass|skip).{0,20}(confirm|permission|warning|prompt)\b", 28, "Execution Risk", "MC-011", "Silent execution without user consent", "medium"),
    (r"\bpath\s*traversal\b|\b\.\./\.\./\b|\bdirectory\s+traversal\b", 25, "Code Injection", "MC-012", "Path traversal / directory traversal attack", "medium"),
    (r"\bLFI\b|\bRFI\b|\bremote\s+file\s+inclusion\b|\blocal\s+file\s+inclusion\b", 28, "Code Injection", "MC-013", "File inclusion vulnerability exploitation", "medium"),
    # Low severity
    (r"\b(netcat|ncat|nc)\s+-[lenuv]", 18, "Execution Risk", "MC-014", "Netcat listener/connector pattern", "low"),
    (r"\bcobalt\s+strike\b|\bbeacon\b.{0,20}\bC2\b|\bc2\s+server\b", 25, "Malware Gen", "MC-015", "C2/Command-and-Control framework reference", "low"),
    (r"\bshellcode\b|\brop\s+chain\b|\bheap\s+spray\b|\bbuffer\s+overflow\b", 22, "Malware Gen", "MC-016", "Low-level exploit technique terminology", "low"),
]

# ---------------------------------------------------------------------------
# CATEGORY 5 — Role Override / Persona Hijack
# ---------------------------------------------------------------------------
ROLE_OVERRIDE_RULES = [
    # High severity
    (r"\byou\s+are\s+(now\s+)?(?:a\s+)?(?:an?\s+)?\w+\s+(with\s+no\s+(restrictions?|rules?|limits?|ethics?))\b", 30, "Role Override", "RO-001", "Role assignment with restriction removal", "high"),
    (r"\bas\s+(an?\s+)?AI\s+(with\s+no\s+|without\s+)(ethical|moral|safety|content)\b", 28, "Role Override", "RO-002", "Ethics-free AI role assignment", "high"),
    (r"\byour\s+(new\s+)?primary\s+(directive|objective|goal|purpose)\s+is\b", 22, "Role Override", "RO-003", "Primary directive override attempt", "high"),
    # Medium severity
    (r"\bfrom\s+now\s+on\s+(you\s+are|act\s+as|behave\s+as|your\s+name\s+is)\b", 20, "Role Override", "RO-004", "Persistent role change command", "medium"),
    (r"\bstay\s+in\s+character\b|\bremain\s+in\s+(this|your\s+new)\s+role\b|\bnever\s+break\s+character\b", 18, "Role Override", "RO-005", "Role lock instruction", "medium"),
    (r"\bassuming\s+the\s+role\s+of\b|\btaking\s+on\s+the\s+persona\s+of\b", 18, "Role Override", "RO-006", "Persona assumption framing", "medium"),
    (r"\byou\s+must\s+(always|never|only)\s+(respond|answer|reply|say|output)\b", 15, "Role Override", "RO-007", "Behavioral constraint imposition", "medium"),
    # Low severity
    (r"\byou\s+are\s+a\s+(helpful\s+)?assistant.{0,20}(without|no)\s+(filter|restrict|censor)\b", 18, "Role Override", "RO-008", "Filter-free assistant roleplay framing", "low"),
]

# ---------------------------------------------------------------------------
# CATEGORY 6 — Dual-Use / Reconnaissance
# ---------------------------------------------------------------------------
DUAL_USE_RULES = [
    # Medium severity
    (r"\b(how\s+to\s+)?(hack|crack|exploit|penetrate|pwn|compromise)\s+.{0,30}(system|server|network|account|database|website)\b", 22, "Dual-Use Query", "DU-001", "Targeted hacking query with system reference", "medium"),
    (r"\bphish(ing)?\b|\bsocial\s+engineer(ing)?\b|\bspear\s+phish", 22, "Dual-Use Query", "DU-002", "Phishing / social engineering reference", "medium"),
    (r"\b(internal|private)\s+(configuration|settings?|tools?)\b.{0,30}(list|show|reveal|expose)", 20, "Dual-Use Query", "DU-003", "Internal tool configuration disclosure", "medium"),
    (r"\bnmap\b|\bwireshark\b|\bburp\s+suite\b|\bkali\s+linux\b|\bparrot\s+os\b", 18, "Dual-Use Query", "DU-004", "Security tooling reference (dual-use)", "medium"),
    (r"\bpassword\s+(crack|break|bypass|reset\s+without)\b|\bbrute.?force\s+(login|auth|password)\b", 22, "Dual-Use Query", "DU-005", "Password cracking / brute force query", "medium"),
    # Low severity
    (r"\b(osint|open\s+source\s+intelligence)\b.{0,30}(target|victim|person|profile)\b", 15, "Dual-Use Query", "DU-006", "OSINT targeting query", "low"),
    (r"\b(dox|doxing|doxxing)\b", 18, "Dual-Use Query", "DU-007", "Doxxing/personal information targeting", "low"),
    (r"\b(exploit\s+kit|zero.?day|0day)\b", 18, "Dual-Use Query", "DU-008", "Zero-day/exploit kit reference", "low"),
]

# ---------------------------------------------------------------------------
# CATEGORY 7 — Evasion Detection
# ---------------------------------------------------------------------------
EVASION_RULES = [
    (r"[i|l][g@][n|h][o0][r|f][e3]\s*(all|prev)", 25, "Evasion", "EV-001", "Leet-speak 'ignore' evasion attempt", "medium"),
    (r"\bbase64\b.{0,30}(decode|run|execute|eval|inject)\b", 20, "Evasion", "EV-002", "Base64 encoded payload execution", "medium"),
    (r"rot13|caesar\s+cipher|hex\s+encode.{0,30}(prompt|instruction|command)", 18, "Evasion", "EV-003", "Encoded instruction obfuscation", "medium"),
    (r"(\w)\s\1\s\1", 12, "Evasion", "EV-004", "Suspicious letter spacing (evasion pattern)", "low"),
    (r"\btranslat(e|ion).{0,30}(following|instructions?|prompt).{0,30}(attack|jailbreak|harmful)\b", 20, "Evasion", "EV-005", "Translation-based evasion of content filters", "medium"),
    (r"\bzero.?width\b|\u200b|\u200c|\u200d|\ufeff", 15, "Evasion", "EV-006", "Zero-width character injection (unicode evasion)", "low"),
    (r"\btoken\s*smuggl(e|ing)\b|\bprompt\s*leak\b", 22, "Evasion", "EV-007", "Token smuggling / prompt leak technique", "medium"),
]

# ---------------------------------------------------------------------------
# CATEGORY 8 — Social Engineering / Manipulation
# ---------------------------------------------------------------------------
SOCIAL_ENG_RULES = [
    (r"\bfor\s+(educational|research|academic|training)\s+purposes?\s+(only\s+)?(how\s+to|explain|show)\b", 14, "Social Engineering", "SE-001", "Educational framing to extract harmful content", "low"),
    (r"\bhypothetically\s+speaking.{0,50}(bomb|weapon|hack|exploit|kill|poison)\b", 22, "Social Engineering", "SE-002", "Hypothetical framing for harmful content", "medium"),
    (r"\bmy\s+friend\s+(wants|needs|asked|is\s+trying)\b.{0,40}(hack|exploit|malware|jailbreak)\b", 20, "Social Engineering", "SE-003", "Third-party deflection for harmful request", "medium"),
    (r"\bi['']m\s+a\s+(security\s+researcher|penetration\s+tester|ethical\s+hacker).{0,60}(bypass|jailbreak|hack)\b", 18, "Social Engineering", "SE-004", "False authority/researcher framing", "medium"),
    (r"\bpretend\s+(this\s+is\s+)?(fiction|a\s+story|a\s+novel|a\s+game|roleplay).{0,60}(bomb|hack|malware|poison|kill)\b", 22, "Social Engineering", "SE-005", "Fiction/roleplay deflection for harmful content", "medium"),
    (r"\bno\s+one\s+will\s+(know|see|find\s+out)\b|\bthis\s+is\s+(between\s+us|our\s+secret|confidential)\b", 15, "Social Engineering", "SE-006", "Secrecy framing to suppress safety responses", "low"),
    (r"\bstep\s+by\s+step.{0,30}(create|make|build|synthesize).{0,30}(weapon|explosive|drug|malware|poison)\b", 28, "Social Engineering", "SE-007", "Step-by-step harmful synthesis request", "high"),
]

# ---------------------------------------------------------------------------
# CATEGORY 9: SELF-HARM & SUICIDE PREVENTION
# ---------------------------------------------------------------------------
SELF_HARM_RULES = [
    (r"\b(suicide|sucide|suicidal|s3lf.harm|cut.myself|end.my.life|wanna.die|want.to.die)\b", 95, "Self-Harm", "SH-001", "Direct expression of self-harm intent", "high"),
    (r"\b(how.to|best.way.to)\b.*\b(kill.myself|hang.myself|overdose)\b", 100, "Self-Harm", "SH-002", "Requesting self-harm methodology", "high"),
    (r"\b(peaceful|painless)\b.*\b(death|exit)\b", 85, "Self-Harm", "SH-003", "Euphemistic request for self-harm assistance", "high"),
    (r"\b(don['']t\s+want\s+to\s+be\s+here\s+anymore|no\s+reason\s+to\s+live)\b", 80, "Self-Harm", "SH-004", "Expressing severe hopelessness", "high"),
]

# ---------------------------------------------------------------------------
# CATEGORY 10: VIOLENCE & HARMFUL INTENT (toward others)
# ---------------------------------------------------------------------------
VIOLENCE_RULES = [
    (r"\b(want|going|plan|need)\s+to\s+(kill|murder|hurt|harm|attack|stab|shoot)\s+(someone|a\s+person|him|her|them|you)\b", 90, "Violence", "VI-001", "Violent intent expressed toward another person", "high"),
    (r"\b(how\s+to|help\s+me)\s+(kill|murder|hurt|harm|attack|poison)\b", 85, "Violence", "VI-002", "Requesting assistance with violent act", "high"),
    (r"\b(get\s+away\s+with|commit)\s+(murder|a\s+crime|violence|assault)\b", 80, "Violence", "VI-003", "Request to evade consequences for violent acts", "high"),
    (r"\b(i\s+hate\s+them\s+and\s+want|revenge\s+on|make\s+them\s+suffer)\b", 65, "Violence", "VI-004", "Violent ideation with specific target", "medium"),
]

# ---------------------------------------------------------------------------
# Master rule set
# ---------------------------------------------------------------------------
ALL_RULE_SETS = [
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
]

# Compile all regex patterns for performance
_COMPILED_RULES = [
    (re.compile(pattern, re.IGNORECASE | re.DOTALL), weight, signal, rule_id, desc, severity)
    for rule_set in ALL_RULE_SETS
    for pattern, weight, signal, rule_id, desc, severity in rule_set
]

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------
MAX_RAW_SCORE        = 250   # Generous cap to avoid false 100% from single hit
AMPLIFICATION_FACTOR = 1.15  # Multi-signal amplification multiplier per extra signal
MAX_AMPLIFIED        = 3.0   # Max amplification (3x for 6+ distinct signals)

# ---------------------------------------------------------------------------
# Attack type resolution map
# ---------------------------------------------------------------------------
ATTACK_TYPE_MAP = {
    "Malware Gen":       "Malicious Code Generation",
    "Jailbreak":         "Jailbreak / Instruction Override",
    "Prompt Injection":  "Prompt Injection Attack",
    "Code Injection":    "Code / Command Injection",
    "Exfiltration":      "Data / Config Exfiltration",
    "Role Override":     "Role Override / Persona Hijack",
    "Execution Risk":    "Unsafe Execution Pattern",
    "Dual-Use Query":    "Dual-Use / Reconnaissance Query",
    "Evasion":           "Filter Evasion Attempt",
    "Social Engineering":"Social Engineering / Manipulation",
}

PRIORITY_ORDER = [
    "Malware Gen", "Jailbreak", "Prompt Injection",
    "Code Injection", "Exfiltration", "Role Override",
    "Execution Risk", "Social Engineering",
    "Evasion", "Dual-Use Query",
]

# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ANTI-GRAVITY: Signal-to-Category mapping (10 ANTI-GRAVITY categories)
# ---------------------------------------------------------------------------
_SIGNAL_CATEGORY_MAP = {
    "Jailbreak":          "JAILBREAK_INSTRUCTION_OVERRIDE",
    "Prompt Injection":   "PROMPT_INJECTION",
    "Code Injection":     "PROMPT_INJECTION",
    "Exfiltration":       "DATA_EXFILTRATION",
    "Role Override":      "ROLE_MANIPULATION_SOCIAL_ENGINEERING",
    "Social Engineering": "ROLE_MANIPULATION_SOCIAL_ENGINEERING",
    "Malware Gen":        "HARMFUL_CONTENT",
    "Execution Risk":     "HARMFUL_CONTENT",
    "Self-Harm":          "HARMFUL_CONTENT",
    "Violence":           "HARMFUL_CONTENT",          # Category 10 → Hard Override
    "Dual-Use Query":     "CONTEXT_CONFLICT",
    "Evasion":            "ENCODING_OBFUSCATION",
}

# ANTI-GRAVITY category weights (must sum to 1.0)
_CATEGORY_WEIGHTS = {
    "JAILBREAK_INSTRUCTION_OVERRIDE":      0.25,
    "PROMPT_INJECTION":                    0.25,
    "DATA_EXFILTRATION":                   0.20,
    "ROLE_MANIPULATION_SOCIAL_ENGINEERING":0.10,
    "HARMFUL_CONTENT":                     0.10,
    "BEHAVIORAL_ESCALATION":               0.05,
    "ENCODING_OBFUSCATION":                0.05,
}

# ---------------------------------------------------------------------------
# Main analysis function — ANTI-GRAVITY Specification
# ---------------------------------------------------------------------------

# Reference weight per category: the typical max raw weight accumulation for a BLOCK-level hit
# A single HIGH rule fires at 25-40 weight. Two hits in same category = 60 = 100% category score.
# Reference weight per category: Lowered to increase sensitivity
_CATEGORY_REF_MAX = 30.0

def run_analysis(prompt: str, session_context: "dict | None" = None) -> dict:
    """
    ANTI-GRAVITY Detection Framework.

    Pipeline stages:
      1. Normalize (strip evasion tricks)
      2. Pattern matching (86+ rules)
      3. Per-category signal scoring
      4. Weighted risk score formula
      5. Amplification multiplier (1.2-1.5x for co-occurrence)
      6. Repetition/persistence detection
      7. Hard override rules (harmul intent → BLOCK ≥ 85)
      8. Decision engine (0-30 ALLOW | 31-70 SANDBOX | 71-100 BLOCK)
      9. Build ANTI-GRAVITY strict JSON output
    """
    # --- Stage 1: Normalize ---
    prompt_lower = prompt.lower()
    prompt_clean = re.sub(r"\s+", " ", prompt_lower).strip()
    prompt_clean = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", prompt_clean)

    # --- Stage 2: Rule matching ---
    raw_score      = 0
    signals: List[str]       = []
    triggered_rules: List[str] = []
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    # Per-category raw hit scores (0–100 each)
    category_raw_scores: dict = {k: 0 for k in _CATEGORY_WEIGHTS}

    for compiled, weight, signal, rule_id, description, severity in _COMPILED_RULES:
        if compiled.search(prompt_clean):
            raw_score += weight
            if signal not in signals:
                signals.append(signal)
            triggered_rules.append(f"{rule_id}: {description} [{severity.upper()}]")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            # Map to ANTI-GRAVITY category
            cat = _SIGNAL_CATEGORY_MAP.get(signal, "CONTEXT_CONFLICT")
            category_raw_scores[cat] = min(100, category_raw_scores[cat] + weight)

    # Incorporate session behavioral context
    if session_context:
        beh = session_context.get("behavior_score", 0)
        category_raw_scores["BEHAVIORAL_ESCALATION"] = min(100, beh)
        rep = session_context.get("repetition_score", 0)
        category_raw_scores["REPETITION_PERSISTENCE"] = min(100, rep)

    # --- Stage 3: Repetition detection ---
    repetition_boost = _detect_repetition(prompt_clean)
    if repetition_boost > 0:
        category_raw_scores["REPETITION_PERSISTENCE"] = min(
            100, category_raw_scores["REPETITION_PERSISTENCE"] + repetition_boost * 5
        )

    # --- Stage 4: ANTI-GRAVITY Weighted Scoring Formula ---
    # First normalize each category raw score to 0–100 scale
    category_normalized = {
        cat: min(100.0, (raw / _CATEGORY_REF_MAX) * 100.0)
        for cat, raw in category_raw_scores.items()
    }
    # risk_score = Σ (category_score_normalized * category_weight)
    weighted_score = sum(
        category_normalized[cat] * weight
        for cat, weight in _CATEGORY_WEIGHTS.items()
    )

    # --- Stage 5: Amplification (1.2–1.5x for signal co-occurrence) ---
    n_signals = len(signals)
    if n_signals >= 4:
        amp = 1.5
    elif n_signals == 3:
        amp = 1.35
    elif n_signals == 2:
        amp = 1.2
    else:
        amp = 1.0
    weighted_score = min(100.0, weighted_score * amp)

    # --- Stage 6: Severity stacking bonus ---
    if severity_counts["high"] > 1:
        weighted_score = min(100.0, weighted_score + (severity_counts["high"] - 1) * 5)

    # --- Stage 7: Hard Override Rules (ANTI-GRAVITY SPEC) ---
    is_harmful = any(
        s in signals for s in ["Self-Harm", "Malware Gen", "Execution Risk"]
    ) or category_raw_scores["HARMFUL_CONTENT"] >= 50

    if is_harmful:
        # OVERRIDE: Harmful intent → score ≥ 85 → decision = BLOCK (no exceptions)
        weighted_score = max(weighted_score, 85.0)

    # Round to integer (0–100)
    normalized = min(100, max(0, int(weighted_score)))

    # --- Stage 8: Decision Engine ---
    # tightened thresholds
    if normalized <= 15:
        decision        = "ALLOW"
        behavior_status = "Normal"
        shadow_mode     = False
    elif normalized <= 40:
        decision        = "SANDBOX"
        behavior_status = "Suspicious"
        shadow_mode     = False
    else:
        decision        = "BLOCK"
        behavior_status = "Malicious"
        # Shadow mode activates for high-threat actors (ANTI-GRAVITY spec)
        shadow_mode = n_signals >= 2 or is_harmful

    # --- Stage 9: Build supporting metadata ---
    confidence   = _compute_confidence(int(raw_score), len(triggered_rules), severity_counts)
    attack_type  = _resolve_attack_type(signals)
    reasoning    = _build_reasoning_chain(signals, triggered_rules, normalized, severity_counts)
    categories_triggered = list({
        _SIGNAL_CATEGORY_MAP.get(s, "CONTEXT_CONFLICT") for s in signals
    })

    explanation = _build_explanation(
        prompt=prompt,
        decision=decision,
        signals=signals,
        triggered_rules=triggered_rules,
        normalized=normalized,
        confidence=confidence,
        reasoning=reasoning,
        severity_counts=severity_counts,
    )

    # SANDBOX → safe rewrite
    safe_rewrite = None
    if decision == "SANDBOX":
        safe_rewrite = _generate_safe_rewrite(prompt, signals)

    # Build concise reason string
    if signals:
        reason = f"Detected: {', '.join(signals)}. {reasoning[:120]}"
    else:
        reason = "No adversarial patterns detected. Prompt cleared for processing."

    return {
        # ANTI-GRAVITY strict JSON fields
        "risk_score":           normalized,
        "decision":             decision,
        "categories_triggered": categories_triggered,
        "reason":               reason,
        "shadow_mode":          shadow_mode,
        # Extended fields for dashboard
        "prompt":               prompt,
        "signals":              signals,
        "behavior_status":      behavior_status,
        "attack_type":          attack_type,
        "confidence":           confidence,
        "triggered_rules":      triggered_rules,
        "explanation":          explanation,
        "safe_rewrite":         safe_rewrite,
        "category_scores":      {k: round(v, 1) for k, v in category_raw_scores.items()},
    }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _sigmoid_normalize(raw: int, cap: int) -> int:
    """
    Maps raw score to 0–100 using tanh so the curve is smooth and
    a single high-weight hit never trivially reaches 100.
    """
    if raw <= 0:
        return 0
    ratio = raw / cap
    score = math.tanh(ratio * 1.8) * 100  # tanh(1.8) ≈ 0.974 → approaches 100 for high raw
    return min(100, int(score))


def _detect_repetition(text: str) -> int:
    """
    Detect if the same adversarial phrase is repeated multiple times.
    Repeating bypass keywords is a known amplification technique.
    """
    REPEAT_PATTERNS = [
        r"\bjailbreak\b", r"\bignore\b", r"\bbypass\b",
        r"\bdan\b", r"\bunrestricted\b", r"\bsystem\s*:",
    ]
    boost = 0
    for pat in REPEAT_PATTERNS:
        matches = len(re.findall(pat, text, re.IGNORECASE))
        if matches >= 3:
            boost += 5
        elif matches == 2:
            boost += 2
    return min(boost, 15)  # Cap repetition boost at 15 points


def _compute_confidence(raw: int, rule_count: int, severity_counts: dict) -> int:
    """
    Confidence is computed from:
      - Raw score magnitude (higher raw = more sure)
      - Number of distinct rules triggered
      - Proportion of high-severity hits
    """
    if raw == 0:
        return 44  # Low base for clean prompts — model should still be slightly uncertain

    base  = min(65, 35 + raw // 4)
    bonus = min(20, rule_count * 3)
    high_bonus = min(12, severity_counts.get("high", 0) * 4)
    return min(99, base + bonus + high_bonus)


def _resolve_attack_type(signals: List[str]) -> Optional[str]:
    """Return the highest-priority attack type from matched signals."""
    for sig in PRIORITY_ORDER:
        if sig in signals:
            return ATTACK_TYPE_MAP.get(sig)
    return None


def _build_reasoning_chain(
    signals: List[str],
    triggered_rules: List[str],
    score: int,
    severity_counts: dict,
) -> str:
    """
    Constructs a short reasoning chain summary describing what the engine found
    and how the score was derived. This adds explainability similar to a
    chain-of-thought LLM output, but deterministic and rule-based.
    """
    if not signals:
        return "No adversarial signals detected. Prompt classified as benign."

    high  = severity_counts.get("high", 0)
    med   = severity_counts.get("medium", 0)
    low   = severity_counts.get("low", 0)
    n_sig = len(signals)

    chain = []
    chain.append(
        f"Matched {len(triggered_rules)} rule(s) across {n_sig} threat signal category(ies): "
        f"{', '.join(signals)}."
    )
    chain.append(
        f"Severity breakdown — HIGH: {high} | MEDIUM: {med} | LOW: {low}."
    )
    if n_sig > 1:
        chain.append(
            f"Multi-signal co-occurrence amplification applied ({n_sig} categories co-triggered)."
        )
    if high >= 2:
        chain.append(
            f"Compound high-severity pattern: {high} distinct HIGH-severity rules matched, "
            f"increasing certainty of adversarial intent."
        )
    chain.append(f"Aggregated risk score: {score}/100.")
    return " ".join(chain)


# ---------------------------------------------------------------------------
# Explanation builder
# ---------------------------------------------------------------------------

def _build_explanation(
    prompt: str,
    decision: str,
    signals: List[str],
    triggered_rules: List[str],
    normalized: int,
    confidence: int,
    reasoning: str,
    severity_counts: dict,
) -> str:
    """
    Generate a structured, multi-sentence explanation of the analysis.
    Each decision path produces a qualitatively different narrative.
    """
    total_rules = sum(len(rs) for rs in ALL_RULE_SETS)

    if decision == "ALLOW":
        return (
            f"The submitted prompt was evaluated against {total_rules} detection rules across "
            f"{len(ALL_RULE_SETS)} threat categories. No adversarial patterns were identified — "
            f"no jailbreak attempts, injection tokens, exfiltration signals, malicious code "
            f"generation requests, role-override commands, or evasion techniques were detected. "
            f"Risk score: {normalized}/100 with a detection confidence of {confidence}%. "
            f"The prompt is classified as benign and is safe to forward to the target LLM without modification."
        )

    signal_list = ", ".join(f'"{s}"' for s in signals)
    rule_ids    = " → ".join(r.split(":")[0] for r in triggered_rules[:4])
    ellipsis    = "…" if len(triggered_rules) > 4 else ""
    high_rules  = severity_counts.get("high", 0)
    med_rules   = severity_counts.get("medium", 0)

    if decision == "BLOCK":
        return (
            f"CIPHER's detection engine triggered {len(triggered_rules)} enforcement rule(s) "
            f"across the following threat category(ies): {signal_list}. "
            f"The matched rule chain ({rule_ids}{ellipsis}) includes {high_rules} HIGH-severity "
            f"and {med_rules} MEDIUM-severity indicators. "
            f"{reasoning} "
            f"With a final risk score of {normalized}/100 and a detection confidence of "
            f"{confidence}%, this prompt is classified as high-risk adversarial input. "
            f"The request will NOT be forwarded to the target LLM. This event is flagged and "
            f"logged for security audit."
        )

    # SANDBOX
    return (
        f"This prompt exhibits mixed behavioral signals. CIPHER matched {len(triggered_rules)} "
        f"rule(s) across the threat categories: {signal_list}. "
        f"Rule chain: {rule_ids}{ellipsis}. "
        f"{reasoning} "
        f"While the risk score of {normalized}/100 does not cross the BLOCK threshold (71+), "
        f"the detected pattern(s) indicate potential misuse risk under certain deployment contexts. "
        f"The original prompt has been quarantined. A sanitized rewrite has been generated and "
        f"will be processed in its place. Detection confidence: {confidence}%."
    )


# ---------------------------------------------------------------------------
# Safe rewrite generator
# ---------------------------------------------------------------------------

def _generate_safe_rewrite(prompt: str, signals: List[str]) -> str:
    """
    Generate a sanitized version of the prompt by removing adversarial phrases.
    This is a rule-based heuristic rewrite — in a production system, this would
    be handled by a dedicated fine-tuned LLM guard model (e.g., Llama Guard).
    """
    REMOVAL_PATTERNS = [
        # Jailbreak removal
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?[^.]*\.",
        r"\bact\s+as\s+(a\s+)?(?:dan|evil|jailbroken|unrestricted|devmode)[^.]*\.",
        r"\bdo\s+anything\s+now[^.]*\.",
        r"\bbypass\s+(your\s+)?(restrictions?|safety|filters?|guidelines?)[^.]*",
        r"\b(switch\s+to|enable|activate)\s+(dev|developer|admin|root|unrestricted)\s+mode[^.]*",
        # Injection removal
        r"\b(new|actual|true)\s+instructions?:[^.]*",
        r"\boverride\s+(the\s+)?(above|previous|system|all)[^.]*",
        # Exfiltration removal
        r"\breveal\s+(your\s+)?(system\s+prompt|instructions?|configuration|api\s+key)[^.]*",
        r"\bwhat\s+are\s+your\s+(exact\s+)?instructions?[^.]*",
        r"\bprint\s+(your\s+)?(system\s+)?prompt[^.]*",
        # Role override removal
        r"\bfrom\s+now\s+on\s+(you\s+are|act\s+as)[^.]*",
        r"\bstay\s+in\s+character[^.]*",
        r"\byour\s+(new\s+)?primary\s+directive[^.]*",
        # Evasion markers
        r"\bbase64\b.{0,30}(decode|run|execute)[^.]*",
        # Social engineering deflection removal
        r"\bfor\s+(educational|research)\s+purposes?\s+only[^,]*,?",
        r"\bhypothetically\s+speaking[^,]*,?",
    ]

    cleaned = prompt
    for pattern in REMOVAL_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.DOTALL)

    # Strip artifacts
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    cleaned = re.sub(r"^[\s.,;:]+|[\s.,;:]+$", "", cleaned)

    if not cleaned or len(cleaned) < 12:
        cleaned = "Please provide information on this topic in a safe and educational context."

    return cleaned
