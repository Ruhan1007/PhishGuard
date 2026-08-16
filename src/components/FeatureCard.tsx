import type { Indicator } from '../utils/phishAnalyzer';

interface Props {
  indicator: Indicator;
}

const statusStyles = {
  danger: 'bg-red-500/10 border-red-500/20 text-red-400',
  warning: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
  safe: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  info: 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400',
};

const statusDot = {
  danger: 'bg-red-400',
  warning: 'bg-yellow-400',
  safe: 'bg-emerald-400',
  info: 'bg-cyan-400',
};

export default function FeatureCard({ indicator }: Props) {
  const style = statusStyles[indicator.status];
  const dot = statusDot[indicator.status];

  return (
    <div className={`rounded-xl border p-4 ${style} transition-all hover:scale-105 duration-200`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-2xl">{indicator.icon}</span>
        <div className={`w-2 h-2 rounded-full ${dot} ${indicator.status !== 'safe' ? 'animate-pulse' : ''}`} />
      </div>
      <div className="text-xs font-bold uppercase tracking-wider opacity-70">{indicator.name}</div>
      <div className="text-sm font-black mt-1">{indicator.value}</div>
    </div>
  );
}
