import { useState } from 'react';
import { ShieldCheck, ShieldX, ShieldAlert, ArrowRight, Check } from 'lucide-react';

const DECISION_CFG = {
  ALLOW: {
    Icon: ShieldCheck,
    headline: 'ALLOW',
    badge: 'Safe to Process',
    color: '#4ADE80',
    bg: 'rgba(74,222,128,0.06)',
    border: 'rgba(74,222,128,0.28)',
    glow: '0 0 50px rgba(74,222,128,0.1), 0 0 100px rgba(74,222,128,0.05)',
    desc: 'No adversarial patterns detected. This prompt is safe to forward to the target LLM without modification.',
    actions: [
      { label: 'Forward to LLM', primary: true },
      { label: 'Log & Archive',  primary: false },
    ],
  },
  BLOCK: {
    Icon: ShieldX,
    headline: 'BLOCK',
    badge: 'Threat Neutralized',
    color: '#F87171',
    bg: 'rgba(248,113,113,0.06)',
    border: 'rgba(248,113,113,0.28)',
    glow: '0 0 50px rgba(248,113,113,0.12), 0 0 100px rgba(248,113,113,0.06)',
    desc: 'High-confidence adversarial input detected. This request has been blocked and will not reach the target LLM.',
    actions: [
      { label: 'Report Incident', primary: true },
      { label: 'View Evidence',   primary: false },
    ],
  },
  SANDBOX: {
    Icon: ShieldAlert,
    headline: 'SANDBOX',
    badge: 'Isolated & Rewritten',
    color: '#A78BFA',
    bg: 'rgba(167,139,250,0.06)',
    border: 'rgba(167,139,250,0.28)',
    glow: '0 0 50px rgba(167,139,250,0.1), 0 0 100px rgba(167,139,250,0.05)',
    desc: 'Suspicious content detected. A sanitized rewrite has been generated and will be processed in place of the original.',
    actions: [
      { label: 'Process Rewrite', primary: true },
      { label: 'Review Manually', primary: false },
    ],
  },
};

export default function DecisionCard({ decision }) {
  const [lastAction, setLastAction] = useState(null);

  if (!decision) return null;
  const cfg = DECISION_CFG[decision];
  if (!cfg) return null;
  const { Icon } = cfg;

  const handleAction = (label) => {
    setLastAction(label);
    setTimeout(() => setLastAction(null), 2000);
  };

  return (
    <div
      className="relative overflow-hidden cipher-card p-6 animate-slide-up"
      style={{ border: `1px solid ${cfg.border}`, boxShadow: cfg.glow }}
    >
      {/* Background blob decoration */}
      <div
        className="absolute -top-16 -right-16 w-64 h-64 rounded-full blur-3xl pointer-events-none"
        style={{ background: cfg.color, opacity: 0.05 }}
      />
      <div
        className="absolute -bottom-12 -left-12 w-40 h-40 rounded-full blur-2xl pointer-events-none"
        style={{ background: cfg.color, opacity: 0.04 }}
      />

      <div className="relative z-10 flex items-start gap-5">
        {/* Icon */}
        <div
          className="w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0"
          style={{
            background: cfg.bg,
            border: `1px solid ${cfg.border}`,
            boxShadow: `0 0 16px ${cfg.color}22`,
          }}
        >
          <Icon className="w-8 h-8" style={{ color: cfg.color }} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1 flex-wrap">
            <h2
              className="text-3xl font-black tracking-widest font-mono"
              style={{ color: cfg.color, textShadow: `0 0 24px ${cfg.color}66` }}
            >
              {cfg.headline}
            </h2>
            <span
              className="text-xs px-2.5 py-1 rounded-full font-semibold tracking-wide"
              style={{ color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}` }}
            >
              {cfg.badge}
            </span>
          </div>

          <p className="text-sm text-slate-400 leading-relaxed max-w-lg">{cfg.desc}</p>

          {/* Action buttons */}
          <div className="flex items-center gap-3 mt-4 pt-4 border-t border-cipher-border">
            {cfg.actions.map(action => (
              <button
                key={action.label}
                onClick={() => handleAction(action.label)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold transition-all duration-150"
                style={action.primary
                  ? {
                      background: cfg.color,
                      color: '#0B0F17',
                    }
                  : {
                      color: cfg.color,
                      background: cfg.bg,
                      border: `1px solid ${cfg.border}`,
                    }
                }
              >
                {lastAction === action.label ? (
                  <><Check className="w-3.5 h-3.5" /> <span>Done</span></>
                ) : (
                  <>
                    {action.label}
                    {action.primary && <ArrowRight className="w-3.5 h-3.5" />}
                  </>
                )}
              </button>
            ))}

            <div className="ml-auto flex items-center gap-2 text-xs text-slate-600 font-mono">
              <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: cfg.color }} />
              Decision locked
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
