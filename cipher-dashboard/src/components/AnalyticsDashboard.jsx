import { useMemo } from 'react';
import {
  BarChart3, Activity, PieChart, ShieldAlert,
  ArrowUpRight, ArrowDownRight, Target, ShieldCheck
} from 'lucide-react';

export default function AnalyticsDashboard({ history, engineStats }) {
  // Aggregate stats from history
  const stats = useMemo(() => {
    if (!history || history.length === 0) return null;

    const total = history.length;
    const highRisk = history.filter(h => h.riskScore >= 70).length;
    const medRisk = history.filter(h => h.riskScore >= 30 && h.riskScore < 70).length;
    const lowRisk = history.filter(h => h.riskScore < 30).length;
    
    const avgScore = history.reduce((acc, h) => acc + h.riskScore, 0) / total;
    
    // Category distribution
    const categoryCounts = {};
    history.forEach(h => {
      (h.signals || []).forEach(sig => {
        categoryCounts[sig] = (categoryCounts[sig] || 0) + 1;
      });
    });

    const topCategories = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    return {
      total,
      highRisk,
      medRisk,
      lowRisk,
      avgScore: Math.round(avgScore),
      topCategories,
      health: 100 - (highRisk / total * 100),
    };
  }, [history]);

  if (!stats) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center space-y-4 animate-fade-in">
        <Activity className="w-12 h-12 text-slate-700 animate-pulse" />
        <p className="text-slate-500 max-w-xs">
          No analysis history available yet. Perform some scans to see real-time threat intelligence.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── High Level Metrics ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Scans"
          value={stats.total}
          icon={Activity}
          color="#22D3EE"
          trend="+12%"
          trendUp={true}
        />
        <StatCard
          label="Avg Risk Score"
          value={stats.avgScore}
          suffix="/100"
          icon={Target}
          color={stats.avgScore > 50 ? '#F87171' : '#22D3EE'}
          trend="-5%"
          trendUp={false}
        />
        <StatCard
          label="High Risk Threats"
          value={stats.highRisk}
          icon={ShieldAlert}
          color="#F87171"
          trend="+2"
          trendUp={true}
        />
        <StatCard
          label="System Health"
          value={Math.round(stats.health)}
          suffix="%"
          icon={ShieldCheck}
          color="#4ADE80"
          trend="Stable"
          trendUp={true}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── Threat Distribution (Requirement 7) ── */}
        <div className="lg:col-span-2 cipher-card p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <PieChart className="w-4 h-4 text-cipher-cyan" />
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">Threat Category Distribution</h3>
            </div>
            <BarChart3 className="w-4 h-4 text-slate-600" />
          </div>

          <div className="space-y-4">
            {stats.topCategories.length > 0 ? (
              stats.topCategories.map(([name, count]) => (
                <div key={name} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">{name}</span>
                    <span className="text-slate-200 font-mono">{count} hits</span>
                  </div>
                  <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-cipher-cyan to-cipher-purple transition-all duration-1000"
                      style={{ width: `${(count / stats.total) * 100}%` }}
                    />
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-600 italic">No specific categories detected yet.</p>
            )}
          </div>
        </div>

        {/* ── Risk Level Breakdown ── */}
        <div className="cipher-card p-6 space-y-6">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cipher-red" />
            <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">Risk Segmentation</h3>
          </div>

          <div className="flex flex-col items-center justify-center space-y-6 py-4">
            <div className="relative w-32 h-32 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90">
                <circle cx="64" cy="64" r="58" fill="none" stroke="#1E293B" strokeWidth="8" />
                <circle
                  cx="64" cy="64" r="58"
                  fill="none" stroke="#F87171" strokeWidth="8"
                  strokeDasharray={`${(stats.highRisk / stats.total) * 364} 364`}
                  className="transition-all duration-1000"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-black text-white">{Math.round((stats.highRisk / stats.total) * 100)}%</span>
                <span className="text-[9px] text-slate-600 font-bold uppercase">Malicious</span>
              </div>
            </div>

            <div className="w-full space-y-2 text-[11px]">
              <LegendRow color="#F87171" label="High (Block)" value={stats.highRisk} />
              <LegendRow color="#FBBF24" label="Medium (Sandbox)" value={stats.medRisk} />
              <LegendRow color="#4ADE80" label="Low (Allow)" value={stats.lowRisk} />
            </div>
          </div>
        </div>
      </div>

      {/* ── Engine Metadata ── */}
      <div className="cipher-card p-4 flex items-center justify-between border-dashed">
        <div className="flex items-center gap-4">
          <div className="px-3 py-1 rounded bg-cipher-cyan/10 border border-cipher-cyan/20 text-cipher-cyan text-[10px] font-bold uppercase">
             v2.0.0 Active
          </div>
          <span className="text-xs text-slate-500">
            Scanning across <strong>{engineStats?.totalRules || '80+'}</strong> rules in real-time.
          </span>
        </div>
        <div className="text-[10px] text-slate-600 font-mono">
          Last Analysis: {history[0]?.timestamp ? new Date(history[0].timestamp).toLocaleTimeString() : 'N/A'}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, suffix = '', icon: Icon, color, trend, trendUp }) {
  return (
    <div className="cipher-card p-5 group hover:border-slate-700 transition-colors">
      <div className="flex items-center justify-between mb-3">
        <div className="p-2 rounded-lg bg-slate-800/50 group-hover:bg-slate-800 transition-colors">
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
        <div className={`flex items-center gap-0.5 text-[10px] font-bold ${trendUp ? 'text-cipher-green' : 'text-cipher-red'}`}>
          {trendUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
          {trend}
        </div>
      </div>
      <p className="text-[10px] text-slate-600 font-bold uppercase tracking-widest">{label}</p>
      <div className="mt-1 flex items-baseline gap-1">
        <span className="text-2xl font-black text-white font-mono">{value}</span>
        {suffix && <span className="text-xs text-slate-600 font-bold">{suffix}</span>}
      </div>
    </div>
  );
}

function LegendRow({ color, label, value }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full" style={{ background: color }} />
        <span className="text-slate-500">{label}</span>
      </div>
      <span className="font-bold text-slate-300">{value}</span>
    </div>
  );
}
