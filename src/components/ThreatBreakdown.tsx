import type { Finding } from '../utils/phishAnalyzer';

interface Props {
  findings: Finding[];
}

const severityConfig = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', bar: 'bg-red-500', border: 'border-red-500/20', icon: '🔴' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/10', bar: 'bg-orange-500', border: 'border-orange-500/20', icon: '🟠' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', bar: 'bg-yellow-500', border: 'border-yellow-500/20', icon: '🟡' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/10', bar: 'bg-blue-500', border: 'border-blue-500/20', icon: '🔵' },
  safe: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', bar: 'bg-emerald-500', border: 'border-emerald-500/20', icon: '🟢' },
  info: { color: 'text-cyan-400', bg: 'bg-cyan-500/10', bar: 'bg-cyan-500', border: 'border-cyan-500/20', icon: '🔵' },
};

export default function ThreatBreakdown({ findings }: Props) {
  const triggered = findings.filter(f => f.triggered);
  const safe = findings.filter(f => !f.triggered);

  return (
    <div className="bg-[#0d1625] border border-white/10 rounded-2xl p-5 space-y-4">
      <h3 className="text-sm font-bold text-white/80 uppercase tracking-widest flex items-center justify-between">
        <span className="flex items-center gap-2">
          <span className="text-red-400">⚠️</span> Threat Breakdown
        </span>
        <span className="text-xs font-normal text-gray-500">
          {triggered.length}/{findings.length} triggered
        </span>
      </h3>

      <div className="space-y-2 max-h-80 overflow-y-auto custom-scroll">
        {/* Triggered findings first */}
        {triggered.map(f => {
          const cfg = severityConfig[f.severity] ?? severityConfig.info;
          return (
            <div
              key={f.id}
              className={`p-3 rounded-xl border ${cfg.bg} ${cfg.border} space-y-1`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm">{cfg.icon}</span>
                  <span className={`text-xs font-bold ${cfg.color}`}>{f.label}</span>
                </div>
                <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full ${cfg.bg} ${cfg.color} border ${cfg.border} font-semibold`}>
                  {f.severity}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 leading-relaxed pl-6">{f.description}</p>
              {f.weight > 0 && (
                <div className="pl-6 flex items-center gap-2 mt-1">
                  <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${cfg.bar} rounded-full transition-all duration-700`}
                      style={{ width: `${Math.min((f.weight / 30) * 100, 100)}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-gray-500">+{f.weight}pts</span>
                </div>
              )}
            </div>
          );
        })}

        {/* Safe findings */}
        {safe.map(f => (
          <div key={f.id} className="p-3 rounded-xl bg-white/3 border border-white/5 flex items-center gap-3 opacity-50">
            <span className="text-sm">🟢</span>
            <div>
              <div className="text-xs text-gray-400 font-semibold">{f.label}</div>
              <div className="text-[11px] text-gray-600">{f.description}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
