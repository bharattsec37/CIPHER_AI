import { useState } from 'react';
import { BookOpen, Crosshair, BarChart2, FileText, ChevronDown, ChevronUp } from 'lucide-react';

export default function ExplainabilityPanel({ attackType, confidence, triggeredRules, explanation }) {
  const [collapsed, setCollapsed] = useState(false);

  const confColor =
    confidence >= 90 ? '#F87171' :
    confidence >= 70 ? '#FBBF24' :
    '#4ADE80';

  return (
    <div className="cipher-card overflow-hidden animate-fade-in">
      {/* Collapsible header */}
      <button
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/[0.02] transition-colors"
        onClick={() => setCollapsed(v => !v)}
        aria-expanded={!collapsed}
      >
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-5 rounded-full bg-cipher-purple" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Explainability Panel
          </h2>
        </div>
        <div className="flex items-center gap-2 text-slate-600">
          <span className="text-xs font-mono">AI Reasoning</span>
          {collapsed
            ? <ChevronDown className="w-4 h-4" />
            : <ChevronUp   className="w-4 h-4" />
          }
        </div>
      </button>

      {!collapsed && (
        <div className="border-t border-cipher-border px-5 pb-5 space-y-4 mt-0">
          {/* Attack type + Confidence */}
          <div className="grid grid-cols-2 gap-3 pt-4">
            {/* Attack type */}
            <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
              <div className="flex items-center gap-1.5 mb-2">
                <Crosshair className="w-3.5 h-3.5 text-cipher-purple" />
                <span className="text-[10px] text-slate-600 uppercase tracking-wider">Attack Type</span>
              </div>
              <p className="text-sm font-semibold text-slate-200">
                {attackType || 'None Identified'}
              </p>
            </div>

            {/* Confidence */}
            <div className="p-3 rounded-xl bg-cipher-bg border border-cipher-border">
              <div className="flex items-center gap-1.5 mb-2">
                <BarChart2 className="w-3.5 h-3.5 text-cipher-cyan" />
                <span className="text-[10px] text-slate-600 uppercase tracking-wider">Confidence</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold font-mono" style={{ color: confColor }}>
                  {confidence}%
                </span>
                <div className="flex-1 h-1.5 bg-cipher-border rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${confidence}%`,
                      background: confColor,
                      boxShadow: `0 0 6px ${confColor}88`,
                    }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Triggered rules */}
          <div>
            <div className="flex items-center gap-2 mb-2.5">
              <BookOpen className="w-3.5 h-3.5 text-slate-500" />
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                Triggered Rules ({triggeredRules.length})
              </h3>
            </div>

            {triggeredRules.length === 0 ? (
              <p className="text-xs text-slate-600 italic py-1">No rules triggered — prompt is clean</p>
            ) : (
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {triggeredRules.map((rule, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2.5 p-2.5 rounded-lg bg-cipher-bg border border-cipher-border animate-slide-in"
                    style={{ animationDelay: `${i * 50}ms` }}
                  >
                    <div className="w-5 h-5 rounded-md bg-cipher-red/10 border border-cipher-red/25 flex items-center justify-center flex-shrink-0 mt-px">
                      <span className="text-[9px] font-bold text-cipher-red">{i + 1}</span>
                    </div>
                    <span className="text-[11px] text-slate-400 font-mono leading-relaxed">{rule}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Explanation */}
          <div>
            <div className="flex items-center gap-2 mb-2.5">
              <FileText className="w-3.5 h-3.5 text-slate-500" />
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                Analysis Explanation
              </h3>
            </div>
            <div className="p-4 rounded-xl bg-cipher-bg border border-cipher-border border-l-2 border-l-cipher-purple">
              <p className="text-sm text-slate-300 leading-relaxed">{explanation}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
