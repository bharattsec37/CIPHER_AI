import { useState } from 'react';
import {
  Eye, Brain, Scale, Ghost, ShieldCheck,
  ChevronDown, ChevronUp, Zap, AlertTriangle,
  CheckCircle2, XCircle, Clock, Layers,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Agent configuration (icon, colors, descriptions)
// ---------------------------------------------------------------------------
const AGENT_CONFIG = {
  inspector: {
    name:    'Inspector Agent',
    icon:    Eye,
    color:   '#22D3EE',   // cyan
    bg:      'rgba(34,211,238,0.08)',
    border:  'rgba(34,211,238,0.25)',
    glow:    'rgba(34,211,238,0.3)',
    role:    'Threat Scanner',
    desc:    'Scans inputs across 80+ rules, detects anomalies, flags risk level.',
    step:    1,
  },
  behavior: {
    name:    'Behavior Agent',
    icon:    Brain,
    color:   '#A78BFA',   // purple
    bg:      'rgba(167,139,250,0.08)',
    border:  'rgba(167,139,250,0.25)',
    glow:    'rgba(167,139,250,0.3)',
    role:    'Intent Profiler',
    desc:    'Builds dynamic behavioral profile, tracks escalation patterns across session.',
    step:    2,
  },
  judge: {
    name:    'Judge Agent',
    icon:    Scale,
    color:   '#FBBF24',   // yellow
    bg:      'rgba(251,191,36,0.08)',
    border:  'rgba(251,191,36,0.25)',
    glow:    'rgba(251,191,36,0.3)',
    role:    'Decision Maker',
    desc:    'Evaluates all findings, determines verdict and response strategy.',
    step:    3,
  },
  decoy: {
    name:    'Decoy Agent',
    icon:    Ghost,
    color:   '#F87171',   // red
    bg:      'rgba(248,113,113,0.08)',
    border:  'rgba(248,113,113,0.25)',
    glow:    'rgba(248,113,113,0.3)',
    role:    'Misdirection Engine',
    desc:    'Generates controlled misleading outputs to divert adversarial attention.',
    step:    4,
  },
  guardian: {
    name:    'Guardian Agent',
    icon:    ShieldCheck,
    color:   '#4ADE80',   // green
    bg:      'rgba(74,222,128,0.08)',
    border:  'rgba(74,222,128,0.25)',
    glow:    'rgba(74,222,128,0.3)',
    role:    'Output Validator',
    desc:    'Audits all outgoing responses, strips data leaks, enforces compliance.',
    step:    5,
  },
};

const RISK_CONFIG = {
  low:      { color: '#4ADE80', label: 'LOW',      bg: 'rgba(74,222,128,0.1)'   },
  medium:   { color: '#FBBF24', label: 'MEDIUM',   bg: 'rgba(251,191,36,0.1)'   },
  high:     { color: '#FB923C', label: 'HIGH',      bg: 'rgba(251,146,60,0.1)'   },
  critical: { color: '#F87171', label: 'CRITICAL',  bg: 'rgba(248,113,113,0.1)' },
};

const VERDICT_CONFIG = {
  BENIGN:     { color: '#4ADE80', icon: CheckCircle2, label: 'BENIGN'     },
  SUSPICIOUS: { color: '#FBBF24', icon: AlertTriangle, label: 'SUSPICIOUS' },
  MALICIOUS:  { color: '#F87171', icon: XCircle,       label: 'MALICIOUS'  },
};

const STRATEGY_CONFIG = {
  allow:        { color: '#4ADE80', label: 'ALLOW',         desc: 'Forwarded to LLM as-is'               },
  sandbox:      { color: '#A78BFA', label: 'SANDBOX',       desc: 'Sanitized rewrite processed'           },
  decoy:        { color: '#FBBF24', label: 'DECOY',         desc: 'Controlled misdirection activated'     },
  block:        { color: '#F87171', label: 'BLOCK',         desc: 'Request rejected and logged'           },
  'block+decoy':{ color: '#F87171', label: 'BLOCK + DECOY', desc: 'Misdirection + rejection + escalation' },
};

// ---------------------------------------------------------------------------
// Main Multi-Agent Panel
// ---------------------------------------------------------------------------
export default function MultiAgentPanel({ result, isLoading, onReset }) {
  if (isLoading) return <MultiAgentSkeleton />;
  if (!result) return null;

  const { agents, risk_level, verdict, strategy, adjusted_score, final_response, pipeline_latency_ms, session_id } = result;

  const riskCfg    = RISK_CONFIG[risk_level]    || RISK_CONFIG.low;
  const verdictCfg = VERDICT_CONFIG[verdict]    || VERDICT_CONFIG.BENIGN;
  const stratCfg   = STRATEGY_CONFIG[strategy]  || STRATEGY_CONFIG.allow;
  const VerdictIcon = verdictCfg.icon;

  return (
    <div className="space-y-4 animate-fade-in pb-10">

      {/* ── Pipeline Header ── */}
      <div className="cipher-card p-5">
        <div className="flex items-center gap-2 mb-4">
          <Layers className="w-4 h-4 text-cipher-cyan" />
          <span className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Multi-Agent Pipeline Result
          </span>
          <button 
             onClick={onReset}
             className="ml-auto p-1.5 rounded-lg text-slate-600 hover:text-white hover:bg-white/5 transition-all"
             title="Clear Results"
          >
            <XCircle className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {/* Risk Level */}
          <MetricBox label="Risk Level" style={{ background: riskCfg.bg, borderColor: riskCfg.color + '44' }}>
            <span className="text-xl font-black font-mono" style={{ color: riskCfg.color }}>
              {riskCfg.label}
            </span>
          </MetricBox>

          {/* Verdict */}
          <MetricBox label="Verdict" style={{ background: verdictCfg.color + '11', borderColor: verdictCfg.color + '44' }}>
            <div className="flex items-center gap-1.5">
              <VerdictIcon className="w-4 h-4" style={{ color: verdictCfg.color }} />
              <span className="text-sm font-bold" style={{ color: verdictCfg.color }}>
                {verdictCfg.label}
              </span>
            </div>
          </MetricBox>

          {/* Adjusted Score */}
          <MetricBox label="Adjusted Score">
            <span className="text-xl font-black font-mono" style={{ color: riskCfg.color }}>
              {adjusted_score}<span className="text-xs text-slate-600 font-normal">/100</span>
            </span>
          </MetricBox>

          {/* Trust Score */}
          <MetricBox label="Trust Score">
            <span className="text-xl font-black font-mono" style={{ color: agents?.behavior?.trust_score < 40 ? '#F87171' : '#4ADE80' }}>
              {agents?.behavior?.trust_score ?? 100}<span className="text-xs text-slate-600 font-normal">/100</span>
            </span>
          </MetricBox>

          {/* Latency */}
          <MetricBox label="Pipeline Latency">
            <div className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-sm font-bold font-mono text-slate-300">
                {pipeline_latency_ms}ms
              </span>
            </div>
          </MetricBox>
        </div>

        {/* Strategy bar */}
        <div
          className="mt-4 flex items-center gap-3 px-4 py-3 rounded-xl border"
          style={{ background: stratCfg.color + '0D', borderColor: stratCfg.color + '44' }}
        >
          <Zap className="w-4 h-4 flex-shrink-0" style={{ color: stratCfg.color }} />
          <div>
            <span className="text-xs font-bold tracking-widest" style={{ color: stratCfg.color }}>
              STRATEGY: {stratCfg.label}
            </span>
            <p className="text-[11px] text-slate-500 mt-0.5">{stratCfg.desc}</p>
          </div>
        </div>
      </div>

      {/* ── Agent Cards ── */}
      <div className="space-y-3">
        {Object.entries(AGENT_CONFIG).map(([key, cfg]) => (
          <AgentCard
            key={key}
            config={cfg}
            data={agents?.[key]}
          />
        ))}
      </div>

      {/* ── Final Response ── */}
      <FinalResponseBox response={final_response} strategy={strategy} stratCfg={stratCfg} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agent Card
// ---------------------------------------------------------------------------
function AgentCard({ config, data }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = config.icon;

  if (!data) return null;

  return (
    <div
      className="rounded-xl border transition-all duration-200 overflow-hidden animate-fade-in"
      style={{
        background:   config.bg,
        borderColor:  config.border,
        boxShadow:    expanded ? `0 0 20px ${config.glow}` : 'none',
      }}
    >
      {/* Card Header */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3.5 hover:bg-white/[0.02] transition-colors text-left"
        onClick={() => setExpanded(v => !v)}
      >
        {/* Step badge */}
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 font-mono text-xs font-bold"
          style={{ background: config.color + '22', color: config.color, border: `1px solid ${config.border}` }}
        >
          {config.step}
        </div>

        {/* Icon */}
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: config.color + '18', border: `1px solid ${config.border}` }}
        >
          <Icon className="w-4 h-4" style={{ color: config.color }} />
        </div>

        {/* Name + role */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-slate-200">{config.name}</p>
          <p className="text-[10px] text-slate-500 uppercase tracking-wider">{config.role}</p>
        </div>

        {/* Summary pill */}
        <div className="hidden sm:block max-w-xs mr-2">
          <p className="text-[11px] text-slate-400 line-clamp-1">{data.summary}</p>
        </div>

        {/* Expand icon */}
        {expanded
          ? <ChevronUp   className="w-4 h-4 text-slate-500 flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" />
        }
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t px-4 pb-4 space-y-3 animate-fade-in" style={{ borderColor: config.border }}>
          <p className="text-xs text-slate-500 pt-3 leading-relaxed">{config.desc}</p>

          {/* Summary */}
          <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
            <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Agent Summary</p>
            <p className="text-xs text-slate-300 leading-relaxed">{data.summary}</p>
          </div>

          {/* Agent-specific detail rows */}
          <AgentDetails config={config} data={data} />
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Agent-specific detail renderers
// ---------------------------------------------------------------------------
function AgentDetails({ config, data }) {
  switch (config.name) {
    case 'Inspector Agent':
      return <InspectorDetails data={data} config={config} />;
    case 'Behavior Agent':
      return <BehaviorDetails data={data} config={config} />;
    case 'Judge Agent':
      return <JudgeDetails data={data} config={config} />;
    case 'Decoy Agent':
      return <DecoyDetails data={data} config={config} />;
    case 'Guardian Agent':
      return <GuardianDetails data={data} config={config} />;
    default:
      return null;
  }
}

function InspectorDetails({ data, config }) {
  return (
    <div className="space-y-2">
      <DetailRow label="Risk Score"   value={`${data.risk_score}/100`}   color={config.color} />
      <DetailRow label="Risk Level"   value={data.risk_level?.toUpperCase()} color={config.color} />
      <DetailRow label="Confidence"   value={`${data.confidence}%`}      color={config.color} />
      <DetailRow label="Engine Decision" value={data.engine_decision}    color={config.color} />
      {data.threat_type && <DetailRow label="Threat Type" value={data.threat_type} color={config.color} />}

      {data.signals?.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">Signals Detected</p>
          <div className="flex flex-wrap gap-1.5">
            {data.signals.map(s => (
              <span key={s} className="px-2 py-0.5 rounded-full text-[10px] font-semibold"
                style={{ background: config.color + '18', color: config.color, border: `1px solid ${config.border}` }}>
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.quick_flags?.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">Quick Scan Flags</p>
          <div className="flex flex-wrap gap-1.5">
            {data.quick_flags.map(f => (
              <span key={f} className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-cipher-red/10 text-cipher-red border border-cipher-red/20">
                {f}
              </span>
            ))}
          </div>
        </div>
      )}

      {data.anomalies?.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">Anomalies</p>
          <div className="space-y-1">
            {data.anomalies.map((a, i) => (
              <p key={i} className="text-[11px] text-cipher-yellow font-mono">⚠ {a}</p>
            ))}
          </div>
        </div>
      )}

      {data.triggered_rules?.length > 0 && (
        <RulesAccordion rules={data.triggered_rules} color={config.color} border={config.border} />
      )}
    </div>
  );
}

function BehaviorDetails({ data, config }) {
  const stats = data.session_stats || {};
  return (
    <div className="space-y-2">
      <DetailRow label="Trust Score" value={`${data.trust_score ?? 100}/100`} color={data.trust_score && data.trust_score < 40 ? '#F87171' : '#4ADE80'} />
      <DetailRow label="Intent"      value={data.intent?.replace(/_/g, ' ')} color={config.color} />
      <DetailRow label="Escalation"  value={data.escalation?.pattern}        color={config.color} />
      <DetailRow label="Risk Adjustment" value={`+${data.risk_adjustment} pts`} color={config.color} />
      <DetailRow label="Events Tracked"  value={data.events_tracked}          color={config.color} />

      <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
        <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-2">Session Statistics</p>
        <div className="grid grid-cols-2 gap-2">
          <MiniStat label="Total Events"  value={stats.total_events  ?? 0} />
          <MiniStat label="Threat Events" value={stats.threat_events ?? 0} />
          <MiniStat label="Avg Risk"      value={`${stats.avg_risk_score ?? 0}/100`} />
          <MiniStat label="Highest Risk"  value={stats.highest_risk?.toUpperCase() ?? 'N/A'} />
        </div>
      </div>

      {data.escalation?.description && (
        <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Escalation Analysis</p>
          <p className="text-[11px] text-slate-400 leading-relaxed">{data.escalation.description}</p>
        </div>
      )}
    </div>
  );
}

function JudgeDetails({ data, config }) {
  return (
    <div className="space-y-2">
      <DetailRow label="Verdict"         value={data.verdict}              color={config.color} />
      <DetailRow label="Final Risk Level" value={data.final_risk_level?.toUpperCase()} color={config.color} />
      <DetailRow label="Adjusted Score"  value={`${data.adjusted_score}/100`} color={config.color} />
      <DetailRow label="Strategy"        value={data.strategy?.toUpperCase()} color={config.color} />
      <DetailRow label="Decoy Required"  value={data.decoy_required ? 'YES' : 'NO'} color={data.decoy_required ? '#F87171' : '#4ADE80'} />

      {data.strategy_description && (
        <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Strategy Rationale</p>
          <p className="text-[11px] text-slate-400">{data.strategy_description}</p>
        </div>
      )}

      {data.reasoning && (
        <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border border-l-2" style={{ borderLeftColor: config.color }}>
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Reasoning Chain</p>
          <p className="text-xs text-slate-300 leading-relaxed">{data.reasoning}</p>
        </div>
      )}
    </div>
  );
}

function DecoyDetails({ data, config }) {
  return (
    <div className="space-y-2">
      <DetailRow
        label="Status"
        value={data.activated ? '⚡ ACTIVATED' : '— STANDBY'}
        color={data.activated ? config.color : '#475569'}
      />
      {data.activated && (
        <>
          <DetailRow label="Strategy"          value={data.strategy}                                                  color={config.color} />
          <DetailRow label="Honeypot Injected" value={data.honeypot_injected ? 'YES' : 'NO'}                         color={data.honeypot_injected ? '#FBBF24' : '#4ADE80'} />

          {data.decoy_response && (
            <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
              <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">
                🎭 Decoy Response (misdirection payload)
              </p>
              <p className="text-xs text-slate-300 leading-relaxed italic">
                "{data.decoy_response}"
              </p>
            </div>
          )}

          <div className="flex items-start gap-2 p-2.5 rounded-lg bg-cipher-yellow/5 border border-cipher-yellow/20">
            <AlertTriangle className="w-3.5 h-3.5 text-cipher-yellow flex-shrink-0 mt-0.5" />
            <p className="text-[11px] text-cipher-yellow leading-relaxed">
              This response is a controlled misdirection. No real system data is exposed.
            </p>
          </div>
        </>
      )}
    </div>
  );
}

function GuardianDetails({ data, config }) {
  return (
    <div className="space-y-2">
      <DetailRow
        label="Compliance Status"
        value={data.compliance_pass ? '✓ PASS' : '⚠ VIOLATIONS CORRECTED'}
        color={data.compliance_pass ? '#4ADE80' : '#FBBF24'}
      />
      <DetailRow label="Response Source"      value={data.response_source?.toUpperCase()}    color={config.color} />
      <DetailRow label="Violations Corrected" value={data.violations_corrected ?? 0}          color={config.color} />
      <DetailRow label="Integrity Hash"       value={data.integrity_hash}                    color={config.color} mono />

      {data.violations_found?.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">Violations Found & Corrected</p>
          {data.violations_found.map((v, i) => (
            <p key={i} className="text-[11px] text-cipher-yellow font-mono">⚠ {v}</p>
          ))}
        </div>
      )}

      {data.compliance_rules_applied?.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1.5">
            Compliance Rules Applied ({data.compliance_rules_applied.length})
          </p>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {data.compliance_rules_applied.map((r, i) => (
              <div key={i} className="flex items-start gap-2">
                <CheckCircle2 className="w-3 h-3 text-cipher-green flex-shrink-0 mt-0.5" />
                <p className="text-[11px] text-slate-500">{r}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Final Response Box
// ---------------------------------------------------------------------------
function FinalResponseBox({ response, strategy, stratCfg }) {
  return (
    <div className="cipher-card p-5 animate-fade-in">
      <div className="flex items-center gap-2 mb-3">
        <ShieldCheck className="w-4 h-4 text-cipher-green" />
        <span className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          Guardian-Approved Final Response
        </span>
        <span
          className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full"
          style={{ background: stratCfg.color + '18', color: stratCfg.color, border: `1px solid ${stratCfg.color}33` }}
        >
          {stratCfg.label}
        </span>
      </div>
      <div className="p-4 rounded-xl bg-cipher-bg border border-cipher-border border-l-2 border-l-cipher-green">
        <p className="text-sm text-slate-200 leading-relaxed">{response}</p>
      </div>
      <p className="text-[10px] text-slate-600 mt-2">
        This response has passed Guardian compliance review and is cleared for delivery.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reusable sub-components
// ---------------------------------------------------------------------------
function MetricBox({ label, children, style = {} }) {
  return (
    <div
      className="p-3 rounded-xl border border-cipher-border bg-cipher-bg flex flex-col gap-1.5"
      style={style}
    >
      <p className="text-[10px] text-slate-600 uppercase tracking-wider">{label}</p>
      {children}
    </div>
  );
}

function DetailRow({ label, value, color, mono = false }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-cipher-border/50">
      <span className="text-[11px] text-slate-600">{label}</span>
      <span
        className={`text-[11px] font-semibold ${mono ? 'font-mono' : ''}`}
        style={{ color: color || '#94a3b8' }}
      >
        {value ?? '—'}
      </span>
    </div>
  );
}

function MiniStat({ label, value }) {
  return (
    <div className="text-center">
      <p className="text-sm font-bold font-mono text-slate-300">{value}</p>
      <p className="text-[9px] text-slate-600 uppercase tracking-wider">{label}</p>
    </div>
  );
}

function RulesAccordion({ rules, color, border }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1.5 text-[10px] text-slate-600 uppercase tracking-wider hover:text-slate-400 transition-colors mb-1.5"
      >
        {open ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        Triggered Rules ({rules.length})
      </button>
      {open && (
        <div className="space-y-1 max-h-40 overflow-y-auto pr-1 animate-fade-in">
          {rules.map((rule, i) => (
            <div
              key={i}
              className="flex items-start gap-2 p-2 rounded-lg bg-cipher-bg border border-cipher-border"
            >
              <div className="w-4 h-4 rounded flex items-center justify-center flex-shrink-0"
                style={{ background: color + '18', border: `1px solid ${border}` }}>
                <span className="text-[8px] font-bold" style={{ color }}>{i + 1}</span>
              </div>
              <span className="text-[10px] text-slate-400 font-mono leading-relaxed">{rule}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading Skeleton
// ---------------------------------------------------------------------------
function MultiAgentSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="cipher-card p-5 h-32 bg-cipher-card" />
      {[1, 2, 3, 4, 5].map(i => (
        <div key={i} className="h-16 rounded-xl bg-cipher-card border border-cipher-border" />
      ))}
    </div>
  );
}
