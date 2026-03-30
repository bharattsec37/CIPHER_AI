import { Shield, Cpu, Wifi, WifiOff, Activity } from 'lucide-react';

export default function Header({ backendOnline, engineStats }) {
  const totalRules = engineStats?.totalRules ?? '95+';
  const categories = engineStats?.categories ?? 9;

  return (
    <header className="sticky top-0 z-50 w-full border-b border-cipher-border bg-cipher-bg/90 backdrop-blur-md flex-shrink-0">
      <div className="flex items-center justify-between px-6 py-3">

        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-9 h-9">
            <div className="absolute inset-0 rounded-lg bg-cipher-cyan/10 border border-cipher-cyan/20" />
            <Shield className="w-5 h-5 text-cipher-cyan relative z-10" />
          </div>
          <div>
            <h1
              className="text-lg font-bold tracking-widest text-cipher-cyan font-mono"
              style={{ textShadow: '0 0 20px rgba(34,211,238,0.4)' }}
            >
              CIPHER
            </h1>
            <p className="text-[10px] text-slate-500 font-medium tracking-wider uppercase -mt-0.5">
              Adaptive Behavioral Defense · LLM Security
            </p>
          </div>
        </div>

        {/* Center stats */}
        <div className="hidden md:flex items-center gap-8">
          <HeaderStat label="Rules" value={String(totalRules)} />
          <HeaderStat label="Categories" value={String(categories)} />
          <HeaderStat label="Engine" value="v2.0" />
          <HeaderStat label="Latency" value="&lt;20ms" />
        </div>

        {/* Right — version + status */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full border border-cipher-border bg-cipher-surface">
            <Cpu className="w-3 h-3 text-slate-500" />
            <span className="text-xs text-slate-400 font-mono">v2.0.0</span>
          </div>

          <BackendStatus online={backendOnline} />
        </div>
      </div>
    </header>
  );
}

function HeaderStat({ label, value }) {
  return (
    <div className="text-center">
      <div
        className="text-sm font-bold font-mono text-cipher-cyan"
        dangerouslySetInnerHTML={{ __html: value }}
      />
      <div className="text-[10px] text-slate-600 uppercase tracking-wider">{label}</div>
    </div>
  );
}

function BackendStatus({ online }) {
  if (online === null) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-cipher-border">
        <Activity className="w-3.5 h-3.5 text-slate-500 animate-pulse" />
        <span className="text-xs text-slate-500">Connecting…</span>
      </div>
    );
  }

  if (online) {
    return (
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-400/10 border border-emerald-400/20">
        <div className="relative flex items-center justify-center w-2 h-2">
          <div className="absolute inset-0 rounded-full bg-emerald-400 animate-ping opacity-60" />
          <div className="w-2 h-2 rounded-full bg-emerald-400" />
        </div>
        <Wifi className="w-3 h-3 text-emerald-400" />
        <span className="text-xs font-semibold text-emerald-400 tracking-wide">System Active</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-cipher-yellow/10 border border-cipher-yellow/20">
      <WifiOff className="w-3.5 h-3.5 text-cipher-yellow" />
      <span className="text-xs font-semibold text-cipher-yellow">Mock Mode</span>
    </div>
  );
}
