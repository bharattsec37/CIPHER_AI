import { useState } from 'react';
import { Wand2, Copy, CheckCheck, ArrowRight } from 'lucide-react';

export default function SandboxRewrite({ decision, safeRewrite }) {
  const [copied, setCopied] = useState(false);

  if (decision !== 'SANDBOX' || !safeRewrite) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(safeRewrite);
    } catch {
      // Fallback for non-HTTPS
      const ta = document.createElement('textarea');
      ta.value = safeRewrite;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="cipher-card overflow-hidden animate-slide-up"
      style={{
        border: '1px solid rgba(167,139,250,0.25)',
        boxShadow: '0 0 30px rgba(167,139,250,0.08)',
      }}
    >
      {/* Header */}
      <div
        className="px-5 py-3.5 flex items-center justify-between border-b border-cipher-border"
        style={{ background: 'rgba(167,139,250,0.05)' }}
      >
        <div className="flex items-center gap-2.5">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'rgba(167,139,250,0.1)', border: '1px solid rgba(167,139,250,0.25)' }}
          >
            <Wand2 className="w-4 h-4 text-cipher-purple" />
          </div>
          <div>
            <p className="text-sm font-semibold text-cipher-purple">Sandbox Rewrite</p>
            <p className="text-[10px] text-slate-600">Sanitized safe-mode version generated</p>
          </div>
        </div>

        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 text-cipher-purple"
          style={{
            border: '1px solid rgba(167,139,250,0.3)',
            background: 'rgba(167,139,250,0.08)',
          }}
        >
          {copied ? (
            <><CheckCheck className="w-3.5 h-3.5" />Copied!</>
          ) : (
            <><Copy className="w-3.5 h-3.5" />Copy</>
          )}
        </button>
      </div>

      {/* Side-by-side panels */}
      <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-cipher-border">
        {/* Original — blurred/redacted */}
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 rounded-full bg-cipher-red" />
            <span className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider">
              Original (Flagged)
            </span>
          </div>
          <div
            className="p-3 rounded-lg text-xs font-mono text-slate-500 leading-relaxed select-none"
            style={{
              background: '#0B0F17',
              border: '1px solid #1E2D42',
              filter: 'blur(1.5px)',
              opacity: 0.5,
              userSelect: 'none',
            }}
          >
            {safeRewrite}
          </div>
          <div className="mt-2">
            <span
              className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full"
              style={{ color: '#F87171', background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)' }}
            >
              ⚠ Adversarial content removed
            </span>
          </div>
        </div>

        {/* Safe rewrite */}
        <div className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 rounded-full bg-cipher-green" />
            <span className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider">
              Safe Rewrite
            </span>
          </div>
          <div
            className="p-3 rounded-lg text-sm font-mono text-slate-300 leading-relaxed"
            style={{ background: '#0B0F17', border: '1px solid rgba(167,139,250,0.15)' }}
          >
            {safeRewrite}
          </div>
          <div className="mt-2 flex items-center gap-2">
            <span
              className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full"
              style={{ color: '#4ADE80', background: 'rgba(74,222,128,0.08)', border: '1px solid rgba(74,222,128,0.2)' }}
            >
              ✓ Cleared for processing
            </span>
            <button className="ml-auto flex items-center gap-1 text-[10px] text-cipher-purple hover:underline">
              Process <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
