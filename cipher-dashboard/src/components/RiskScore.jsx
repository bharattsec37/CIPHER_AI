import { useEffect, useRef } from 'react';
import { TrendingUp } from 'lucide-react';

function getRiskConfig(score) {
  if (score <= 30)  return { color: '#4ADE80', label: 'Low Risk',    tier: 0 };
  if (score <= 70)  return { color: '#FBBF24', label: 'Medium Risk', tier: 1 };
  return               { color: '#F87171', label: 'High Risk',   tier: 2 };
}

const TIERS = [
  { label: 'Low',    color: '#4ADE80', range: '0–30'  },
  { label: 'Medium', color: '#FBBF24', range: '31–70' },
  { label: 'High',   color: '#F87171', range: '71–100' },
];

export default function RiskScore({ score }) {
  const { color, label, tier } = getRiskConfig(score);
  const barRef = useRef(null);

  // Animate bar from 0 to score
  useEffect(() => {
    if (!barRef.current) return;
    barRef.current.style.width = '0%';
    const t = setTimeout(() => {
      if (barRef.current) barRef.current.style.width = `${score}%`;
    }, 60);
    return () => clearTimeout(t);
  }, [score]);

  // SVG arc
  const R = 50, CX = 60, CY = 60;
  const ARC_START = 150; // degrees (bottom-left)
  const ARC_END   = 30;  // degrees (bottom-right)
  const SPAN      = 360 - ARC_START + ARC_END; // 240°

  const toRad = (deg) => (deg * Math.PI) / 180;

  function arcPath(cx, cy, r, startDeg, endDeg) {
    const s = toRad(startDeg);
    const e = toRad(endDeg);
    const x1 = cx + r * Math.cos(s);
    const y1 = cy + r * Math.sin(s);
    const x2 = cx + r * Math.cos(e);
    const y2 = cy + r * Math.sin(e);
    const large = endDeg - startDeg > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  }

  // We draw a 240° arc (from 150° → 30° clockwise = going through 240/360/0/30)
  const bgPath    = arcPath(CX, CY, R, ARC_START, ARC_START + SPAN);
  const fillAngle = ARC_START + (score / 100) * SPAN;
  const fillPath  = score > 0 ? arcPath(CX, CY, R, ARC_START, fillAngle) : '';

  const strokeLen = 2 * Math.PI * R * (SPAN / 360);

  return (
    <div className="cipher-card p-5 animate-fade-in">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-5 rounded-full bg-cipher-purple" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Risk Score</h2>
        </div>
        <TrendingUp className="w-4 h-4 text-slate-600" />
      </div>

      <div className="flex items-center gap-5">
        {/* SVG Gauge */}
        <div className="relative flex-shrink-0">
          <svg width="120" height="120" viewBox="0 0 120 120">
            {/* Background arc */}
            <path d={bgPath} fill="none" stroke="#1E2D42" strokeWidth="9" strokeLinecap="round" />
            {/* Score arc */}
            {fillPath && (
              <path
                d={fillPath}
                fill="none"
                stroke={color}
                strokeWidth="9"
                strokeLinecap="round"
                style={{
                  filter: `drop-shadow(0 0 6px ${color}99)`,
                  transition: 'all 0.8s cubic-bezier(0.4,0,0.2,1)',
                }}
              />
            )}
          </svg>
          {/* Center label */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-black font-mono leading-none" style={{ color }}>
              {score}
            </span>
            <span className="text-[9px] text-slate-600 uppercase tracking-widest">/ 100</span>
          </div>
        </div>

        {/* Details */}
        <div className="flex-1 space-y-3">
          <div>
            <p className="text-base font-bold" style={{ color }}>{label}</p>
            <p className="text-xs text-slate-600 mt-0.5">Threat probability index</p>
          </div>

          {/* Linear bar */}
          <div className="space-y-1">
            <div className="w-full h-2 bg-cipher-border rounded-full overflow-hidden">
              <div
                ref={barRef}
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{ width: '0%', background: color, boxShadow: `0 0 8px ${color}88` }}
              />
            </div>
            <div className="flex justify-between text-[9px] font-mono text-slate-700">
              <span>0</span><span>30</span><span>70</span><span>100</span>
            </div>
          </div>

          {/* Tier pills */}
          <div className="flex gap-1.5">
            {TIERS.map((t, i) => (
              <span
                key={t.label}
                className="text-[10px] px-2 py-0.5 rounded-full border font-medium transition-all duration-300"
                style={{
                  color: t.color,
                  borderColor: `${t.color}${tier === i ? '60' : '22'}`,
                  background: `${t.color}${tier === i ? '18' : '08'}`,
                  opacity: tier === i ? 1 : 0.35,
                  boxShadow: tier === i ? `0 0 8px ${t.color}33` : 'none',
                }}
              >
                {t.label}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
