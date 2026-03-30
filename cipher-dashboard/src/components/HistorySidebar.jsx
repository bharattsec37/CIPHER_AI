import { History, Shield, ShieldCheck, ShieldX, ShieldAlert, ChevronRight, Trash2, TrendingUp } from 'lucide-react';

const DEC_CFG = {
  ALLOW:   { Icon: ShieldCheck, color: '#4ADE80', bg: 'rgba(74,222,128,0.08)',  border: 'rgba(74,222,128,0.2)'  },
  BLOCK:   { Icon: ShieldX,     color: '#F87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.2)' },
  SANDBOX: { Icon: ShieldAlert, color: '#A78BFA', bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.2)' },
};

function MiniBar({ score }) {
  const color = score <= 30 ? '#4ADE80' : score <= 70 ? '#FBBF24' : '#F87171';
  return (
    <div className="flex items-center gap-1.5">
      <div className="flex-1 h-1 bg-cipher-border rounded-full overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{ width: `${score}%`, background: color, boxShadow: `0 0 4px ${color}66` }}
        />
      </div>
      <span className="text-[10px] font-mono w-6 text-right" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

function fmt(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export default function HistorySidebar({ history, onSelect, onClear, activeId }) {
  const counts = {
    BLOCK:   history.filter(h => h.decision === 'BLOCK').length,
    ALLOW:   history.filter(h => h.decision === 'ALLOW').length,
    SANDBOX: history.filter(h => h.decision === 'SANDBOX').length,
  };

  return (
    <aside className="h-full flex flex-col bg-cipher-surface">
      {/* Header */}
      <div className="px-4 py-4 border-b border-cipher-border flex-shrink-0">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cipher-cyan" />
            <span className="text-sm font-semibold text-slate-300">Scan History</span>
          </div>
          {history.length > 0 && (
            <button
              onClick={onClear}
              title="Clear history"
              className="p-1.5 rounded-lg text-slate-600 hover:text-cipher-red hover:bg-cipher-red/10 transition-all duration-150"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Mini counters */}
        <div className="grid grid-cols-3 gap-1.5">
          {[
            { label: 'Block',   value: counts.BLOCK,   color: '#F87171' },
            { label: 'Allow',   value: counts.ALLOW,   color: '#4ADE80' },
            { label: 'Sandbox', value: counts.SANDBOX, color: '#A78BFA' },
          ].map(c => (
            <div key={c.label} className="flex flex-col items-center py-1.5 rounded-lg bg-cipher-card border border-cipher-border">
              <span className="text-sm font-bold font-mono" style={{ color: c.color }}>{c.value}</span>
              <span className="text-[9px] text-slate-600 uppercase tracking-wider">{c.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Risk trend sparkbar (Layer 4) */}
      {history.length > 1 && (
        <div className="px-4 py-3 border-b border-cipher-border flex-shrink-0">
          <div className="flex items-center gap-1.5 mb-2">
            <TrendingUp className="w-3 h-3 text-slate-600" />
            <span className="text-[10px] text-slate-600 uppercase tracking-wider">Risk Trend (last {Math.min(history.length, 12)})</span>
          </div>
          <div className="space-y-1">
            <div className="flex items-end gap-0.5 h-9">
              {history.slice(0, 12).reverse().map((item) => {
                const h = Math.max((item.riskScore / 100) * 36, 3);
                const color = item.riskScore <= 30 ? '#4ADE80' : item.riskScore <= 70 ? '#FBBF24' : '#F87171';
                const isActive = item.id === activeId;
                return (
                  <div
                    key={item.id}
                    title={`Risk: ${item.riskScore} — ${item.decision}`}
                    onClick={() => onSelect(item)}
                    className="flex-1 rounded-sm cursor-pointer transition-opacity duration-150 hover:opacity-100"
                    style={{
                      height: `${h}px`,
                      background: color,
                      opacity: isActive ? 1 : 0.45,
                      boxShadow: isActive ? `0 0 4px ${color}` : 'none',
                    }}
                  />
                );
              })}
            </div>
            {/* Time axis labels */}
            <div className="flex items-center justify-between text-[8px] text-slate-700 font-mono uppercase tracking-tighter">
              <span>{fmt(history.slice(0, 12).reverse()[0].timestamp)}</span>
              <span className="w-px h-1 bg-slate-800" />
              <span>Now</span>
            </div>
          </div>
        </div>
      )}

      {/* History list */}
      <div className="flex-1 overflow-y-auto">
        {history.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 gap-2 text-center px-4">
            <Shield className="w-8 h-8 text-slate-700" />
            <p className="text-xs text-slate-600">No scans yet</p>
            <p className="text-[10px] text-slate-700">Submit a prompt to begin</p>
          </div>
        ) : (
          <div className="p-2 space-y-1">
            {history.map((item, i) => {
              const cfg = DEC_CFG[item.decision] || DEC_CFG.ALLOW;
              const { Icon } = cfg;
              const isActive = item.id === activeId;

              return (
                <button
                  key={item.id}
                  onClick={() => onSelect(item)}
                  className="w-full text-left p-3 rounded-xl border transition-all duration-150 group animate-slide-in"
                  style={{
                    animationDelay: `${i * 35}ms`,
                    background: isActive ? cfg.bg : 'transparent',
                    borderColor: isActive ? cfg.border : 'transparent',
                  }}
                  onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = '#131B2A'; }}
                  onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
                >
                  <div className="flex items-start gap-2.5">
                    {/* Decision icon */}
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                      style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
                    >
                      <Icon className="w-3.5 h-3.5" style={{ color: cfg.color }} />
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-1.5">
                        {item.prompt}
                      </p>
                      <MiniBar score={item.riskScore} />
                      <div className="flex items-center justify-between mt-1.5">
                        <span className="text-[10px] font-bold tracking-wider" style={{ color: cfg.color }}>
                          {item.decision}
                        </span>
                        <span className="text-[10px] text-slate-600 font-mono">
                          {item.timestamp ? fmt(item.timestamp) : ''}
                        </span>
                      </div>
                    </div>

                    <ChevronRight
                      className="w-3 h-3 flex-shrink-0 mt-2"
                      style={{ color: isActive ? cfg.color : '#374151' }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </aside>
  );
}
