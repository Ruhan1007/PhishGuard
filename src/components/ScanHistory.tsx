import type { HistoryEntry } from './PhishGuard';

interface Props {
  history: HistoryEntry[];
  onRecan: (url: string) => void;
}

export default function ScanHistory({ history, onRecan }: Props) {
  if (history.length === 0) {
    return (
      <div className="max-w-4xl mx-auto py-20 text-center space-y-4">
        <div className="text-6xl opacity-30">📋</div>
        <h3 className="text-xl font-bold text-gray-500">No Scan History Yet</h3>
        <p className="text-gray-600 text-sm">URLs you analyze will appear here for review.</p>
      </div>
    );
  }

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-400';
    if (score >= 45) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  const getRiskBg = (score: number) => {
    if (score >= 75) return 'border-red-500/20 bg-red-500/5';
    if (score >= 45) return 'border-yellow-500/20 bg-yellow-500/5';
    return 'border-emerald-500/20 bg-emerald-500/5';
  };

  const getRiskIcon = (score: number) => {
    if (score >= 75) return '🚨';
    if (score >= 45) return '⚠️';
    return '✅';
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-white">Scan History</h2>
          <p className="text-xs text-gray-500 mt-1">{history.length} URL{history.length !== 1 ? 's' : ''} analyzed this session</p>
        </div>
        <div className="flex gap-2 text-xs">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400">
            <span>🚨</span> {history.filter(h => h.score >= 75).length} High Risk
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-400">
            <span>⚠️</span> {history.filter(h => h.score >= 45 && h.score < 75).length} Suspicious
          </div>
          <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <span>✅</span> {history.filter(h => h.score < 45).length} Safe
          </div>
        </div>
      </div>

      {/* Stats bar */}
      <div className="w-full h-3 bg-white/5 rounded-full overflow-hidden flex">
        {history.filter(h => h.score >= 75).length > 0 && (
          <div
            className="h-full bg-red-500 transition-all"
            style={{ width: `${(history.filter(h => h.score >= 75).length / history.length) * 100}%` }}
          />
        )}
        {history.filter(h => h.score >= 45 && h.score < 75).length > 0 && (
          <div
            className="h-full bg-yellow-500 transition-all"
            style={{ width: `${(history.filter(h => h.score >= 45 && h.score < 75).length / history.length) * 100}%` }}
          />
        )}
        {history.filter(h => h.score < 45).length > 0 && (
          <div
            className="h-full bg-emerald-500 transition-all"
            style={{ width: `${(history.filter(h => h.score < 45).length / history.length) * 100}%` }}
          />
        )}
      </div>

      {/* History list */}
      <div className="space-y-3">
        {history.map((entry, i) => (
          <div
            key={i}
            className={`group relative flex items-center gap-4 p-4 rounded-xl border ${getRiskBg(entry.score)} transition-all hover:scale-[1.01] cursor-default`}
          >
            <div className="text-2xl flex-shrink-0">{getRiskIcon(entry.score)}</div>
            <div className="flex-1 min-w-0">
              <div className="text-sm text-white/80 truncate font-mono">{entry.url}</div>
              <div className="flex items-center gap-3 mt-1">
                <span className={`text-xs font-semibold ${getRiskColor(entry.score)}`}>{entry.verdict}</span>
                <span className="text-xs text-gray-600">
                  {entry.timestamp.toLocaleTimeString()}
                </span>
              </div>
            </div>
            <div className="flex-shrink-0 flex items-center gap-3">
              <div className={`text-xl font-black ${getRiskColor(entry.score)}`}>
                {entry.score}
              </div>
              <button
                onClick={() => onRecan(entry.url)}
                className="opacity-0 group-hover:opacity-100 transition-all px-3 py-1.5 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/30 text-cyan-400 text-xs rounded-lg"
              >
                Re-scan
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
