interface Props {
  url: string;
}

export default function SafeBrowsingBadge({ url }: Props) {
  const handleCheck = () => {
    const encoded = encodeURIComponent(url);
    window.open(`https://transparencyreport.google.com/safe-browsing/search?url=${encoded}`, '_blank', 'noopener,noreferrer');
  };

  return (
    <button
      onClick={handleCheck}
      className="flex items-center gap-2 px-4 py-2 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 hover:border-blue-500/40 rounded-lg text-xs text-blue-400 hover:text-blue-300 transition-all"
      title="Check on Google Safe Browsing"
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.35-4.35" />
      </svg>
      Verify on Google Safe Browsing ↗
    </button>
  );
}
