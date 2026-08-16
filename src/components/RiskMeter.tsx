interface Props {
  score: number;
}

export default function RiskMeter({ score }: Props) {
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const progress = ((100 - score) / 100) * circumference;

  const color = score >= 75 ? '#f87171' : score >= 45 ? '#facc15' : '#34d399';
  const label = score >= 75 ? 'HIGH' : score >= 45 ? 'MED' : 'LOW';

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="100" height="100" viewBox="0 0 100 100" className="-rotate-90">
        {/* Background track */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="8"
        />
        {/* Progress arc */}
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          style={{ transition: 'stroke-dashoffset 1s ease-in-out, stroke 0.5s ease' }}
          filter={`drop-shadow(0 0 6px ${color})`}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-2xl font-black" style={{ color }}>{score}</span>
        <span className="text-[9px] font-bold tracking-widest" style={{ color }}>{label}</span>
      </div>
    </div>
  );
}
