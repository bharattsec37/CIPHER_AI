import { Tag } from 'lucide-react';

const SIGNAL_STYLES = {
  'Jailbreak':        { color: '#F87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
  'Prompt Injection': { color: '#F87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
  'Role Override':    { color: '#FB923C', bg: 'rgba(251,146,60,0.08)',  border: 'rgba(251,146,60,0.25)'  },
  'Exfiltration':     { color: '#A78BFA', bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.25)' },
  'Dual-Use Query':   { color: '#FBBF24', bg: 'rgba(251,191,36,0.08)',  border: 'rgba(251,191,36,0.25)'  },
  'Malware Gen':      { color: '#F87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
  'Code Injection':   { color: '#FB923C', bg: 'rgba(251,146,60,0.08)',  border: 'rgba(251,146,60,0.25)'  },
  'Execution Risk':   { color: '#F87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
};

const DEFAULT_STYLE = { color: '#22D3EE', bg: 'rgba(34,211,238,0.08)', border: 'rgba(34,211,238,0.25)' };

export default function Signals({ signals }) {
  const intensity = Math.min(signals.length * 25, 100);

  return (
    <div className="cipher-card p-5 animate-fade-in">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-5 rounded-full bg-cipher-red" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Threat Signals</h2>
        </div>
        <span className="text-xs font-mono text-slate-600">
          {signals.length} {signals.length === 1 ? 'signal' : 'signals'} detected
        </span>
      </div>

      {signals.length === 0 ? (
        <div className="flex items-center gap-3 py-4">
          <div className="w-8 h-8 rounded-full bg-cipher-green/10 border border-cipher-green/20 flex items-center justify-center">
            <Tag className="w-4 h-4 text-cipher-green" />
          </div>
          <div>
            <p className="text-sm text-slate-400 font-medium">No signals detected</p>
            <p className="text-xs text-slate-600">Prompt appears clean across all categories</p>
          </div>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-2 mb-4">
            {signals.map((sig, i) => {
              const s = SIGNAL_STYLES[sig] || DEFAULT_STYLE;
              return (
                <span
                  key={sig}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border animate-fade-in"
                  style={{
                    color: s.color,
                    background: s.bg,
                    borderColor: s.border,
                    animationDelay: `${i * 70}ms`,
                  }}
                >
                  <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: s.color }} />
                  {sig}
                </span>
              );
            })}
          </div>

          {/* Intensity bar */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[10px] text-slate-600 uppercase tracking-wider">
              <span>Signal Intensity</span>
              <span className="font-mono">{intensity}%</span>
            </div>
            <div className="w-full h-1.5 bg-cipher-border rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{
                  width: `${intensity}%`,
                  background: 'linear-gradient(90deg, #FBBF24, #F87171)',
                  boxShadow: '0 0 8px rgba(248,113,113,0.4)',
                }}
              />
            </div>
          </div>
        </>
      )}
    </div>
  );
}
