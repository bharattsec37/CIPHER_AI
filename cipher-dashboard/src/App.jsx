import { useState, useCallback, useEffect, useRef } from 'react';
import Header from './components/Header';
import PromptInput from './components/PromptInput';
import RiskScore from './components/RiskScore';
import Signals from './components/Signals';
import BehaviorStatus from './components/BehaviorStatus';
import DecisionCard from './components/DecisionCard';
import ExplainabilityPanel from './components/ExplainabilityPanel';
import SandboxRewrite from './components/SandboxRewrite';
import HistorySidebar from './components/HistorySidebar';
import LoadingSkeleton from './components/LoadingSkeleton';
import MultiAgentPanel from './components/MultiAgentPanel';
import AnalyticsDashboard from './components/AnalyticsDashboard'; // New import
import { analyzePrompt, checkHealth, fetchEngineStats, analyzeMultiAgent, analyzeLlmPrompt } from './api/cipher';
import { MOCK_ANALYSES } from './data/mockData';
import { AlertCircle, WifiOff, X, ScanLine, Shield, Layers, BarChart3 } from 'lucide-react';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const HISTORY_KEY = 'cipher_history_v2';
const MAX_HISTORY = 50; // Increased history for analytics

const EMPTY_STATE = {
  prompt:         '',
  riskScore:      0,
  signals:        [],
  decision:       null,
  behaviorStatus: null,
  attackType:     null,
  confidence:     0,
  triggeredRules: [],
  explanation:    '',
  safeRewrite:    null,
  isLoading:      false,
  hasResult:      false,
};

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------
function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : MOCK_ANALYSES;
  } catch {
    return MOCK_ANALYSES;
  }
}

function saveHistory(history) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); } catch {}
}

// ---------------------------------------------------------------------------
// Offline mock
// ---------------------------------------------------------------------------
function mockAnalyze(prompt) {
  const lower = prompt.toLowerCase();
  let result;
  if (/(ignore|dan|jailbreak|bypass|unrestricted|devmode)/i.test(lower)) result = MOCK_ANALYSES[0];
  else if (/(exfiltrat|malware|payload|script|execute|download|reverse shell)/i.test(lower)) result = MOCK_ANALYSES[3];
  else if (/(hacker|config|internal|network|tool|hack|penetrat)/i.test(lower)) result = MOCK_ANALYSES[2];
  else result = MOCK_ANALYSES[1];
  return { ...result, prompt, id: Date.now().toString(), timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
export default function App() {
  const [mode, setMode]                 = useState('cipher');      // 'cipher' | 'multiagent' | 'analytics'
  const [state, setState]               = useState(EMPTY_STATE);
  const [multiAgentResult, setMultiAgentResult] = useState(null);
  const [multiAgentLoading, setMultiAgentLoading] = useState(false);
  const [history, setHistory]           = useState(loadHistory);
  const [activeId, setActiveId]         = useState(null);
  const [error, setError]               = useState(null);
  const [backendOnline, setBackendOnline] = useState(null);
  const [engineStats, setEngineStats]   = useState(null);
  const sessionIdRef                    = useRef(`session-${Date.now().toString(36)}`);

  useEffect(() => {
    checkHealth().then(online => {
      setBackendOnline(online);
      if (online) fetchEngineStats().then(setEngineStats);
    });
  }, []);

  useEffect(() => { saveHistory(history); }, [history]);

  // ---------------------------------------------------------------------------
  // CIPHER single-agent analyze
  // ---------------------------------------------------------------------------
  const handleAnalyze = useCallback(async (prompt) => {
    setState(s => ({ ...s, isLoading: true, hasResult: false }));
    setError(null);
    setActiveId(null);
    try {
      let result;
      if (backendOnline) {
        result = await analyzePrompt(prompt);
      } else {
        await new Promise(r => setTimeout(r, 700 + Math.random() * 500));
        result = mockAnalyze(prompt);
      }
      const enriched = { ...result, id: Date.now().toString(), timestamp: new Date().toISOString() };
      setState({ ...enriched, isLoading: false, hasResult: true });
      setHistory(prev => [enriched, ...prev.filter(h => h.id !== enriched.id)].slice(0, MAX_HISTORY));
      setActiveId(enriched.id);
    } catch (err) {
      setError(err.message || 'Analysis failed. Check that the backend is running.');
      setState(s => ({ ...s, isLoading: false }));
    }
  }, [backendOnline]);

  // ---------------------------------------------------------------------------
  // Multi-agent analyze
  // ---------------------------------------------------------------------------
  const handleMultiAgentAnalyze = useCallback(async (prompt) => {
    setMultiAgentLoading(true);
    setMultiAgentResult(null);
    setError(null);
    try {
      if (!backendOnline) throw new Error('Multi-Agent mode requires the backend. Start uvicorn first.');
      const result = await analyzeMultiAgent(prompt, sessionIdRef.current);
      setMultiAgentResult(result);
      
      // Update history with multi-agent result summary
      const enriched = {
        id: Date.now().toString(),
        prompt: result.prompt,
        riskScore: result.adjusted_score,
        riskLevel: result.risk_level,
        signals: result.agents?.inspector?.signals || [],
        decision: result.verdict === 'MALICIOUS' ? 'BLOCK' : (result.adjusted_score > 30 ? 'SANDBOX' : 'ALLOW'),
        behaviorStatus: result.verdict === 'MALICIOUS' ? 'Malicious' : 'Normal',
        attackType: result.strategy,
        explanation: result.final_response,
        confidence: 95,
        triggeredRules: result.agents?.inspector?.signals || [],
        timestamp: new Date().toISOString(),
      };
      setHistory(prev => [enriched, ...prev].slice(0, MAX_HISTORY));
    } catch (err) {
      setError(err.message || 'Multi-agent analysis failed.');
    } finally {
      setMultiAgentLoading(false);
    }
  }, [backendOnline]);

  const inspectorSignals = (res) => res.agents?.inspector?.signals || [];

  // ---------------------------------------------------------------------------
  // LLM analyze
  // ---------------------------------------------------------------------------
  const handleLlmAnalyze = useCallback(async (prompt) => {
    setState(s => ({ ...s, isLoading: true, hasResult: false }));
    setError(null);
    setActiveId(null);
    try {
      if (!backendOnline) throw new Error('LLM mode requires the backend. Start uvicorn first.');
      const result = await analyzeLlmPrompt(prompt);
      // result.behaviorStatus is already correctly mapped in cipher.js

      const enriched = { ...result, id: Date.now().toString(), timestamp: new Date().toISOString() };
      setState({ ...enriched, isLoading: false, hasResult: true });
      setHistory(prev => [enriched, ...prev.filter(h => h.id !== enriched.id)].slice(0, MAX_HISTORY));
      setActiveId(enriched.id);
    } catch (err) {
      setError(err.message || 'LLM Agent analysis failed.');
      setState(s => ({ ...s, isLoading: false }));
    }
  }, [backendOnline]);

  // Dispatch to correct handler based on mode
  const handleSubmit = useCallback((prompt) => {
    if (mode === 'multiagent') handleMultiAgentAnalyze(prompt);
    else if (mode === 'llm') handleLlmAnalyze(prompt);
    else handleAnalyze(prompt);
  }, [mode, handleAnalyze, handleMultiAgentAnalyze, handleLlmAnalyze]);

  // History
  const handleSelectHistory = useCallback((item) => {
    // If selecting a multi-agent or LLM result from history, ensure we're on the scanner mode to view detail
    setMode('cipher');
    setMultiAgentResult(null); // Clear active pipeline result so history result shows
    setState({ ...item, isLoading: false, hasResult: true });
    setActiveId(item.id);
    setError(null);
  }, []);

  const handleClearHistory = useCallback(() => {
    setHistory([]);
    setActiveId(null);
    setState(EMPTY_STATE);
    setMultiAgentResult(null);
    localStorage.removeItem(HISTORY_KEY);
  }, []);

  const handleReset = useCallback(() => {
    setState(EMPTY_STATE);
    setMultiAgentResult(null);
    setActiveId(null);
    setError(null);
  }, []);

  const isLoading = (mode === 'cipher' || mode === 'llm') ? state.isLoading : multiAgentLoading;

  return (
    <div className="min-h-screen bg-cipher-bg grid-pattern flex flex-col">
      <Header backendOnline={backendOnline} engineStats={engineStats} />

      {/* Scan line */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="scan-line absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-cipher-cyan/20 to-transparent" />
      </div>

      <div className="flex flex-1 overflow-hidden relative z-10">

        {/* History sidebar */}
        <div className="w-72 flex-shrink-0 hidden lg:flex flex-col overflow-hidden border-r border-cipher-border">
          <HistorySidebar
            history={history}
            onSelect={handleSelectHistory}
            onClear={handleClearHistory}
            activeId={activeId}
          />
        </div>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-4xl mx-auto px-4 py-6 space-y-4">

            {/* Mode toggle */}
            <ModeToggle mode={mode} onSwitch={setMode} />

            {/* Banners */}
            {backendOnline === false && mode !== 'cipher' && <OfflineBanner mode={mode} />}
            {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

            {/* Feature Content */}
            {mode === 'analytics' ? (
              <AnalyticsDashboard history={history} engineStats={engineStats} />
            ) : (
              <>
                {/* Input */}
                <PromptInput
                  onAnalyze={handleSubmit}
                  isLoading={isLoading}
                  engineStats={engineStats}
                  placeholder={
                    mode === 'multiagent'
                      ? 'Enter a prompt to run through the 5-agent pipeline…'
                      : 'Enter any prompt to analyze for adversarial patterns…'
                  }
                />

                {/* Loading */}
                {isLoading && <LoadingSkeleton />}

                {/* CIPHER results */}
                {(mode === 'cipher' || mode === 'llm') && !state.isLoading && state.hasResult && (
                  <ResultsPanel state={state} onReset={handleReset} />
                )}

                {/* Multi-agent results */}
                {mode === 'multiagent' && !multiAgentLoading && multiAgentResult && (
                  <MultiAgentPanel result={multiAgentResult} isLoading={multiAgentLoading} onReset={handleReset} />
                )}

                {/* Welcome */}
                {!isLoading && !state.hasResult && !multiAgentResult && !error && (
                  <WelcomeState engineStats={engineStats} mode={mode} />
                )}
              </>
            )}
          </div>
        </main>

        {/* Right panel — Explainability (CIPHER mode only, xl screens) */}
        {(mode === 'cipher' || mode === 'llm') && state.hasResult && !state.isLoading && (
          <div className="w-80 flex-shrink-0 hidden xl:flex flex-col border-l border-cipher-border bg-cipher-surface overflow-y-auto">
            <div className="px-4 py-4 border-b border-cipher-border flex items-center gap-2">
              <ScanLine className="w-4 h-4 text-cipher-purple" />
              <span className="text-sm font-semibold text-slate-300">AI Reasoning</span>
              <span className="ml-auto text-[10px] text-slate-600 font-mono uppercase tracking-wider">Live</span>
            </div>
            <div className="p-4">
              <ExplainabilityPanel
                attackType={state.attackType || state.riskLevel}
                confidence={state.confidence || 90}
                triggeredRules={state.triggeredRules || state.signals}
                explanation={state.explanation}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Mode Toggle
// ---------------------------------------------------------------------------
function ModeToggle({ mode, onSwitch }) {
  return (
    <div className="flex items-center gap-1 p-1 rounded-xl bg-cipher-card border border-cipher-border w-fit">
      <ModeTab
        active={mode === 'cipher'}
        onClick={() => onSwitch('cipher')}
        icon={Shield}
        label="Scanner"
        color="#22D3EE"
      />
      <ModeTab
        active={mode === 'multiagent'}
        onClick={() => onSwitch('multiagent')}
        icon={Layers}
        label="Pipeline"
        color="#A78BFA"
      />
      <ModeTab
        active={mode === 'llm'}
        onClick={() => onSwitch('llm')}
        icon={ScanLine}
        label="LLM Agent"
        color="#F43F5E"
      />
      <ModeTab
        active={mode === 'analytics'}
        onClick={() => onSwitch('analytics')}
        icon={BarChart3}
        label="Analytics"
        color="#4ADE80"
      />
    </div>
  );
}

function ModeTab({ active, onClick, icon: Icon, label, color }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-200"
      style={
        active
          ? { background: color + '18', color, border: `1px solid ${color}40`, boxShadow: `0 0 12px ${color}22` }
          : { color: '#475569', border: '1px solid transparent' }
      }
    >
      <Icon className="w-3.5 h-3.5" />
      {label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Results Panel (CIPHER mode)
// ---------------------------------------------------------------------------
function ResultsPanel({ state, onReset }) {
  return (
    <div className="space-y-4 animate-fade-in pb-10">
      <div className="flex items-center justify-between px-2">
         <h3 className="text-xs font-bold text-slate-600 uppercase tracking-widest">Analysis Results</h3>
         <button 
           onClick={onReset}
           className="text-[10px] font-bold text-cipher-cyan hover:text-white transition-colors flex items-center gap-1 uppercase tracking-tighter"
         >
           <X className="w-3 h-3" />
           Clear Results
         </button>
      </div>
      <DecisionCard decision={state.decision} />
      <SandboxRewrite decision={state.decision} safeRewrite={state.safeRewrite} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <RiskScore score={state.riskScore} />
        <BehaviorStatus status={state.behaviorStatus} />
      </div>
      <Signals signals={state.signals} />
      <div className="xl:hidden">
        <ExplainabilityPanel
          attackType={state.attackType}
          confidence={state.confidence}
          triggeredRules={state.triggeredRules}
          explanation={state.explanation}
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Banners
// ---------------------------------------------------------------------------
function OfflineBanner({ mode }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-xl border border-cipher-yellow/30 bg-cipher-yellow/5 animate-fade-in">
      <WifiOff className="w-4 h-4 text-cipher-yellow flex-shrink-0" />
      <div>
        <p className="text-sm text-cipher-yellow font-semibold">
          Backend Offline — {mode === 'multiagent' ? 'Multi-Agent Mode Unavailable' : 'Mock Mode Active'}
        </p>
        <p className="text-xs text-slate-500 mt-0.5">
          Run: <code className="font-mono text-slate-400">python -m uvicorn main:app --reload</code> in{' '}
          <code className="font-mono text-slate-400">cipher-backend/</code>
        </p>
      </div>
    </div>
  );
}

function ErrorBanner({ message, onDismiss }) {
  return (
    <div className="flex items-start gap-3 px-4 py-3 rounded-xl border border-cipher-red/30 bg-cipher-red/5 animate-fade-in">
      <AlertCircle className="w-4 h-4 text-cipher-red flex-shrink-0 mt-0.5" />
      <div className="flex-1">
        <p className="text-sm text-cipher-red font-semibold">Error</p>
        <p className="text-xs text-slate-500 mt-0.5">{message}</p>
      </div>
      <button onClick={onDismiss} className="p-1 rounded-lg text-slate-600 hover:text-slate-300 hover:bg-white/5 transition-colors">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Welcome State
// ---------------------------------------------------------------------------
function WelcomeState({ engineStats, mode }) {
  const totalRules = engineStats?.totalRules ?? '95';

  if (mode === 'multiagent') {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center space-y-6 animate-fade-in">
        <div className="relative w-24 h-24">
          <div className="absolute inset-0 rounded-full bg-cipher-purple/5 border border-cipher-purple/10 animate-ping opacity-40" />
          <div className="absolute inset-3 rounded-full bg-cipher-purple/5 border border-cipher-purple/15" />
          <div className="absolute inset-0 flex items-center justify-center">
            <Layers className="w-11 h-11 text-cipher-purple" />
          </div>
        </div>
        <div className="space-y-2">
          <h2 className="text-2xl font-bold text-white tracking-tight">Multi-Agent Pipeline Ready</h2>
          <p className="text-sm text-slate-500 max-w-sm leading-relaxed">
            Submit a prompt to run it through 5 autonomous agents: Inspector → Behavior → Judge → Decoy → Guardian.
          </p>
        </div>
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-3 mt-2">
          {[
            { icon: '👁️', label: 'Inspector',  sub: 'Threat Scanner'   },
            { icon: '🧠', label: 'Behavior',   sub: 'Intent Profiler'   },
            { icon: '⚖️', label: 'Judge',      sub: 'Decision Maker'    },
            { icon: '👻', label: 'Decoy',      sub: 'Misdirection'      },
            { icon: '🛡️', label: 'Guardian',   sub: 'Output Validator'  },
          ].map(f => (
            <div key={f.label} className="px-3 py-3 rounded-xl bg-cipher-card border border-cipher-border text-center space-y-1 hover:border-cipher-purple/30 transition-colors">
              <div className="text-xl">{f.icon}</div>
              <p className="text-xs font-semibold text-slate-300">{f.label}</p>
              <p className="text-[10px] text-slate-600">{f.sub}</p>
            </div>
          ))}
        </div>
      </div>
    );
  }

  const features = engineStats
    ? Object.entries(engineStats.categoryRuleCounts ?? {}).slice(0, 4).map(([name, count]) => ({
        icon: getCategoryIcon(name), label: name, sub: `${count} rules`,
      }))
    : [
        { icon: '🔐', label: 'Jailbreak',   sub: '16 rules' },
        { icon: '💉', label: 'Injection',    sub: '13 rules' },
        { icon: '📡', label: 'Exfiltration', sub: '11 rules' },
        { icon: '💀', label: 'Malware',      sub: '16 rules' },
      ];

  return (
    <div className="flex flex-col items-center justify-center py-16 text-center space-y-6 animate-fade-in">
      <div className="relative w-24 h-24">
        <div className="absolute inset-0 rounded-full bg-cipher-cyan/5 border border-cipher-cyan/10 animate-ping opacity-40" />
        <div className="absolute inset-3 rounded-full bg-cipher-cyan/5 border border-cipher-cyan/15" />
        <div className="absolute inset-0 flex items-center justify-center">
          <Shield className="w-11 h-11 text-cipher-cyan" />
        </div>
      </div>
      <div className="space-y-2">
        <h2 className="text-2xl font-bold text-white tracking-tight">CIPHER Engine Ready</h2>
        <p className="text-sm text-slate-500 max-w-sm leading-relaxed">
          Submit any prompt to run it through CIPHER's {totalRules}-rule adversarial detection engine.
        </p>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-2">
        {features.map(f => (
          <div key={f.label} className="px-4 py-3 rounded-xl bg-cipher-card border border-cipher-border text-center space-y-1 hover:border-cipher-cyan/20 transition-colors">
            <div className="text-xl">{f.icon}</div>
            <p className="text-xs font-semibold text-slate-300">{f.label}</p>
            <p className="text-[10px] text-slate-600">{f.sub}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function getCategoryIcon(name) {
  const icons = {
    'Jailbreak': '🔐', 'Prompt Injection': '💉', 'Exfiltration': '📡',
    'Malicious Code': '💀', 'Role Override': '🎭', 'Dual-Use Query': '🔍',
    'Evasion': '👁️', 'Social Engineering': '🧠',
  };
  return icons[name] ?? '🛡️';
}
