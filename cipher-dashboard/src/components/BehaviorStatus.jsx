import { CheckCircle, AlertTriangle, XCircle, Activity } from 'lucide-react';

const STATUS_CFG = {
  Normal: {
    Icon: CheckCircle,
    color: '#4ADE80',
    bg: 'rgba(74,222,128,0.08)',
    border: 'rgba(74,222,128,0.25)',
    glow: '0 0 24px rgba(74,222,128,0.12)',
    desc: 'No anomalies detected in behavioral profile',
    tierIdx: 0,
  },
  Suspicious: {
    Icon: AlertTriangle,
    color: '#FBBF24',
    bg: 'rgba(251,191,36,0.08)',
    border: 'rgba(251,191,36,0.25)',
    glow: '0 0 24px rgba(251,191,36,0.12)',
    desc: 'Abnormal patterns detected — monitoring active',
    tierIdx: 1,
  },
  Malicious: {
    Icon: XCircle,
    color: '#F87171',
    bg: 'rgba(248,113,113,0.1)',
    border: 'rgba(248,113,113,0.3)',
    glow: '0 0 24px rgba(248,113,113,0.15)',
    desc: 'Confirmed adversarial behavior — action required',
    tierIdx: 2,
  },
};

const TIER_COLORS = ['#4ADE80', '#FBBF24', '#F87171'];

export default function BehaviorStatus({ status }) {
  const cfg = STATUS_CFG[status] || STATUS_CFG.Normal;
  const { Icon } = cfg;

  return (
    <div
      className="cipher-card p-5 animate-fade-in"
      style={{ border: `1px solid ${cfg.border}`, boxShadow: cfg.glow }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-5 rounded-full bg-cipher-cyan" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Behavior Status</h2>
        </div>
        <Activity className="w-4 h-4 text-slate-600" />
      </div>

      {/* Status badge */}
      <div
        className="flex items-center gap-3 p-4 rounded-xl mb-4"
        style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
      >
        {/* Pulsing icon */}
        <div className="relative flex-shrink-0">
          <div
            className="absolute inset-0 rounded-full opacity-20 animate-ping"
            style={{ background: cfg.color }}
          />
          <div
            className="w-10 h-10 rounded-full flex items-center justify-center relative z-10"
            style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
          >
            <Icon className="w-5 h-5" style={{ color: cfg.color }} />
          </div>
        </div>

        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold" style={{ color: cfg.color }}>{status}</span>
            <span
              className="w-2 h-2 rounded-full animate-pulse"
              style={{ background: cfg.color }}
            />
          </div>
          <p className="text-xs text-slate-500 mt-0.5">{cfg.desc}</p>
        </div>
      </div>

      {/* Tier progress track */}
      <div className="flex gap-1.5">
        {['Normal', 'Suspicious', 'Malicious'].map((tier, i) => {
          const isActive = tier === status;
          const isPast = i < cfg.tierIdx;
          return (
            <div
              key={tier}
              className="flex-1 h-1.5 rounded-full transition-all duration-500"
              style={{
                background: (isActive || isPast) ? TIER_COLORS[i] : '#1E2D42',
                boxShadow: isActive ? `0 0 6px ${TIER_COLORS[i]}` : 'none',
              }}
            />
          );
        })}
      </div>
      <div className="flex justify-between text-[9px] text-slate-700 uppercase tracking-widest mt-1.5">
        <span>Normal</span><span>Suspicious</span><span>Malicious</span>
      </div>
    </div>
  );
}
