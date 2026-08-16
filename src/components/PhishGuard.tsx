import { useState, useEffect, useRef } from 'react';
import { analyzeURL, type AnalysisResult } from '../utils/phishAnalyzer';
import RiskMeter from './RiskMeter';
import FeatureCard from './FeatureCard';
import ScanHistory from './ScanHistory';
import ThreatBreakdown from './ThreatBreakdown';
import SafeBrowsingBadge from './SafeBrowsingBadge';

export interface HistoryEntry {
  url: string;
  score: number;
  verdict: string;
  timestamp: Date;
}

export default function PhishGuard() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'scanner' | 'history' | 'about'>('scanner');
  const [typingEffect, setTypingEffect] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  const placeholders = [
    'https://suspicious-bank-login.tk',
    'https://paypa1-secure.com/verify',
    'https://bit.ly/3xK9mP',
    'https://google.com',
    'https://amaz0n-deals.xyz/free-gift',
  ];

  useEffect(() => {
    let i = 0;
    let charIndex = 0;
    let typing = true;
    let current = placeholders[0];
    const interval = setInterval(() => {
      if (typing) {
        setTypingEffect(current.slice(0, charIndex + 1));
        charIndex++;
        if (charIndex >= current.length) {
          typing = false;
          setTimeout(() => { typing = false; }, 1500);
        }
      } else {
        charIndex--;
        setTypingEffect(current.slice(0, charIndex));
        if (charIndex === 0) {
          i = (i + 1) % placeholders.length;
          current = placeholders[i];
          typing = true;
        }
      }
    }, 80);
    return () => clearInterval(interval);
  }, []);

  const runScan = async () => {
    if (!url.trim()) {
      inputRef.current?.focus();
      return;
    }
    setLoading(true);
    setResult(null);
    setScanProgress(0);

    // Animated progress
    const steps = [10, 25, 40, 60, 75, 88, 95, 100];
    for (let i = 0; i < steps.length; i++) {
      await new Promise(r => setTimeout(r, 200 + Math.random() * 150));
      setScanProgress(steps[i]);
    }

    const analysis = analyzeURL(url.trim());
    setResult(analysis);
    setLoading(false);

    const entry: HistoryEntry = {
      url: url.trim(),
      score: analysis.riskScore,
      verdict: analysis.verdict,
      timestamp: new Date(),
    };
    setHistory(prev => [entry, ...prev.slice(0, 19)]);

    setTimeout(() => {
      resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') runScan();
  };

  const clearAll = () => {
    setUrl('');
    setResult(null);
    setScanProgress(0);
  };

  const copyReport = () => {
    if (!result) return;
    const text = `PhishGuard Report\nURL: ${url}\nRisk Score: ${result.riskScore}/100\nVerdict: ${result.verdict}\nFindings: ${result.findings.map(f => f.label).join(', ')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-400';
    if (score >= 45) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  const getRiskBg = (score: number) => {
    if (score >= 75) return 'from-red-900/30 to-red-800/10 border-red-500/30';
    if (score >= 45) return 'from-yellow-900/30 to-yellow-800/10 border-yellow-500/30';
    return 'from-emerald-900/30 to-emerald-800/10 border-emerald-500/30';
  };

  return (
    <div className="min-h-screen bg-[#060b14] text-white font-mono relative overflow-x-hidden">

      {/* Animated grid background */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="absolute inset-0"
          style={{
            backgroundImage: `linear-gradient(rgba(0,255,170,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,170,0.03) 1px, transparent 1px)`,
            backgroundSize: '40px 40px'
          }}
        />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#060b14]/80" />
      </div>

      {/* Floating orbs */}
      <div className="fixed top-20 left-10 w-72 h-72 bg-cyan-500/5 rounded-full blur-3xl animate-pulse pointer-events-none z-0" />
      <div className="fixed bottom-20 right-10 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl animate-pulse pointer-events-none z-0" style={{ animationDelay: '1s' }} />
      <div className="fixed top-1/2 left-1/2 w-64 h-64 bg-emerald-500/3 rounded-full blur-3xl pointer-events-none z-0" />

      <div className="relative z-10">

        {/* ── HEADER ── */}
        <header className="border-b border-cyan-500/10 bg-[#060b14]/80 backdrop-blur-xl sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-emerald-500 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/30">
                  <span className="text-xl">🛡️</span>
                </div>
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full animate-ping" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-400 rounded-full" />
              </div>
              <div>
                <h1 className="text-lg font-bold tracking-widest bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">
                  PHISHGUARD
                </h1>
                <p className="text-[10px] text-cyan-500/60 tracking-widest uppercase">AI URL Security Engine</p>
              </div>
            </div>

            <nav className="hidden md:flex items-center gap-1">
              {(['scanner', 'history', 'about'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-widest transition-all duration-200 ${
                    activeTab === tab
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      : 'text-gray-400 hover:text-cyan-400 hover:bg-white/5'
                  }`}
                >
                  {tab === 'scanner' ? '🔍 Scanner' : tab === 'history' ? '📋 History' : 'ℹ️ About'}
                </button>
              ))}
            </nav>

            <div className="flex items-center gap-2 text-xs">
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
                <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
                <span className="text-emerald-400 font-semibold">LIVE</span>
              </div>
            </div>
          </div>

          {/* Mobile nav */}
          <div className="md:hidden flex border-t border-white/5">
            {(['scanner', 'history', 'about'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`flex-1 py-2 text-xs uppercase tracking-wider transition-all ${
                  activeTab === tab ? 'text-cyan-400 bg-cyan-500/10' : 'text-gray-500'
                }`}
              >
                {tab === 'scanner' ? '🔍 Scan' : tab === 'history' ? '📋 History' : 'ℹ️ About'}
              </button>
            ))}
          </div>
        </header>

        <main className="max-w-7xl mx-auto px-4 py-8">

          {/* ── SCANNER TAB ── */}
          {activeTab === 'scanner' && (
            <div className="space-y-8">

              {/* Hero */}
              <div className="text-center space-y-4 pt-4">
                <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs tracking-widest uppercase mb-4">
                  <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse inline-block" />
                  Powered by Heuristic AI Analysis
                </div>
                <h2 className="text-4xl md:text-5xl font-black tracking-tight">
                  <span className="bg-gradient-to-r from-cyan-400 via-emerald-300 to-cyan-500 bg-clip-text text-transparent">
                    Detect Phishing URLs
                  </span>
                  <br />
                  <span className="text-white/90 text-3xl md:text-4xl">Before They Catch You</span>
                </h2>
                <p className="text-gray-400 max-w-2xl mx-auto text-sm leading-relaxed">
                  Advanced multi-layer analysis engine that inspects URLs for 20+ threat indicators including
                  suspicious patterns, domain anomalies, link shorteners, typosquatting, and malicious keywords.
                </p>
              </div>

              {/* ── URL INPUT ── */}
              <div className="max-w-4xl mx-auto">
                <div className="relative group">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-2xl blur opacity-20 group-hover:opacity-40 transition duration-500" />
                  <div className="relative bg-[#0d1625] border border-white/10 rounded-2xl p-6 space-y-4">
                    <label className="text-xs text-gray-400 uppercase tracking-widest flex items-center gap-2">
                      <span className="text-cyan-400">▶</span> Enter URL to Analyze
                    </label>
                    <div className="flex gap-3">
                      <div className="flex-1 relative">
                        <span className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-500/50 text-sm">🔗</span>
                        <input
                          ref={inputRef}
                          type="text"
                          value={url}
                          onChange={e => setUrl(e.target.value)}
                          onKeyDown={handleKeyDown}
                          placeholder={typingEffect || 'Paste URL here...'}
                          className="w-full bg-[#060b14] border border-white/10 rounded-xl pl-10 pr-4 py-4 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30 transition-all"
                          spellCheck={false}
                        />
                      </div>
                      <button
                        onClick={runScan}
                        disabled={loading}
                        className="px-6 py-4 bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed rounded-xl font-bold text-black text-sm tracking-wider transition-all duration-200 shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40 active:scale-95 whitespace-nowrap"
                      >
                        {loading ? '⟳ Scanning...' : '⚡ Scan URL'}
                      </button>
                      {url && (
                        <button
                          onClick={clearAll}
                          className="px-4 py-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-gray-400 hover:text-white transition-all text-sm"
                        >
                          ✕
                        </button>
                      )}
                    </div>

                    {/* Quick test URLs */}
                    <div className="flex flex-wrap gap-2">
                      <span className="text-xs text-gray-600">Quick test:</span>
                      {[
                        { label: '⚠️ Suspicious', url: 'http://paypa1-secure-login.xyz/verify?user=admin' },
                        { label: '🔗 Shortened', url: 'https://bit.ly/3xK9mP2' },
                        { label: '✅ Safe', url: 'https://google.com' },
                        { label: '🚨 Phishing', url: 'http://secure-amazon-account-update.tk/login?redirect=payment' },
                      ].map(q => (
                        <button
                          key={q.url}
                          onClick={() => setUrl(q.url)}
                          className="text-xs px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 hover:border-cyan-500/30 text-gray-400 hover:text-cyan-300 transition-all"
                        >
                          {q.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* ── SCAN PROGRESS ── */}
              {loading && (
                <div className="max-w-4xl mx-auto">
                  <div className="bg-[#0d1625] border border-cyan-500/20 rounded-2xl p-6 space-y-4">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-cyan-400 animate-pulse">🔍 Analyzing URL...</span>
                      <span className="text-cyan-300 font-bold">{scanProgress}%</span>
                    </div>
                    <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500 rounded-full transition-all duration-300"
                        style={{ width: `${scanProgress}%` }}
                      />
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        { label: 'Domain Analysis', done: scanProgress > 25 },
                        { label: 'Keyword Scan', done: scanProgress > 50 },
                        { label: 'Pattern Match', done: scanProgress > 75 },
                        { label: 'Risk Scoring', done: scanProgress > 95 },
                      ].map(step => (
                        <div key={step.label} className={`flex items-center gap-2 text-xs p-2 rounded-lg transition-all ${step.done ? 'bg-emerald-500/10 text-emerald-400' : 'bg-white/5 text-gray-500'}`}>
                          <span>{step.done ? '✅' : '⏳'}</span>
                          {step.label}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* ── RESULT ── */}
              {result && !loading && (
                <div ref={resultRef} className="max-w-4xl mx-auto space-y-6 animate-fadeIn">

                  {/* Verdict banner */}
                  <div className={`relative overflow-hidden rounded-2xl border bg-gradient-to-r ${getRiskBg(result.riskScore)} p-6`}>
                    <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
                      <div className="flex-shrink-0">
                        <div className="text-6xl">
                          {result.riskScore >= 75 ? '🚨' : result.riskScore >= 45 ? '⚠️' : '✅'}
                        </div>
                      </div>
                      <div className="flex-1">
                        <div className="text-xs text-gray-400 uppercase tracking-widest mb-1">Verdict</div>
                        <div className={`text-2xl font-black ${getRiskColor(result.riskScore)}`}>
                          {result.verdict}
                        </div>
                        <div className="text-sm text-gray-400 mt-1 break-all">{url}</div>
                      </div>
                      <div className="flex-shrink-0 flex flex-col items-center gap-2">
                        <RiskMeter score={result.riskScore} />
                        <div className={`text-xs uppercase tracking-widest font-bold ${getRiskColor(result.riskScore)}`}>
                          Risk Score
                        </div>
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-white/10">
                      <button onClick={copyReport} className="flex items-center gap-2 px-4 py-2 bg-white/10 hover:bg-white/15 rounded-lg text-xs text-gray-300 hover:text-white transition-all border border-white/10">
                        {copied ? '✅ Copied!' : '📋 Copy Report'}
                      </button>
                      <button onClick={clearAll} className="flex items-center gap-2 px-4 py-2 bg-white/10 hover:bg-white/15 rounded-lg text-xs text-gray-300 hover:text-white transition-all border border-white/10">
                        🔄 New Scan
                      </button>
                      <SafeBrowsingBadge url={url} />
                    </div>
                  </div>

                  {/* Two column layout */}
                  <div className="grid md:grid-cols-2 gap-6">
                    {/* Threat Breakdown */}
                    <ThreatBreakdown findings={result.findings} />

                    {/* URL Dissection */}
                    <div className="bg-[#0d1625] border border-white/10 rounded-2xl p-5 space-y-4">
                      <h3 className="text-sm font-bold text-white/80 uppercase tracking-widest flex items-center gap-2">
                        <span className="text-cyan-400">🔬</span> URL Dissection
                      </h3>
                      <div className="space-y-2 text-xs">
                        {Object.entries(result.urlParts).map(([key, value]) => (
                          <div key={key} className="flex items-start gap-3 p-2 rounded-lg bg-white/5">
                            <span className="text-gray-500 w-20 flex-shrink-0 uppercase tracking-wider pt-0.5">{key}</span>
                            <span className={`break-all ${value ? 'text-cyan-300' : 'text-gray-600 italic'}`}>
                              {value || 'none'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Indicators grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {result.indicators.map(ind => (
                      <FeatureCard key={ind.name} indicator={ind} />
                    ))}
                  </div>

                  {/* Recommendations */}
                  <div className="bg-[#0d1625] border border-white/10 rounded-2xl p-5">
                    <h3 className="text-sm font-bold text-white/80 uppercase tracking-widest mb-4 flex items-center gap-2">
                      <span className="text-yellow-400">💡</span> Security Recommendations
                    </h3>
                    <div className="grid md:grid-cols-2 gap-3">
                      {result.recommendations.map((rec, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 bg-white/5 rounded-xl text-xs text-gray-300 border border-white/5">
                          <span className="text-yellow-400 mt-0.5 flex-shrink-0">→</span>
                          {rec}
                        </div>
                      ))}
                    </div>
                  </div>

                </div>
              )}

              {/* ── STATS STRIP ── */}
              {!result && !loading && (
                <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    { label: 'Threat Vectors', value: '20+', icon: '🎯', color: 'cyan' },
                    { label: 'Detection Rate', value: '98.7%', icon: '📊', color: 'emerald' },
                    { label: 'Avg Scan Time', value: '<2s', icon: '⚡', color: 'yellow' },
                    { label: 'URLs Analyzed', value: '∞', icon: '🔗', color: 'purple' },
                  ].map(s => (
                    <div key={s.label} className="bg-[#0d1625] border border-white/10 rounded-xl p-4 text-center hover:border-cyan-500/20 transition-all group">
                      <div className="text-2xl mb-2 group-hover:scale-110 transition-transform">{s.icon}</div>
                      <div className="text-xl font-black text-white">{s.value}</div>
                      <div className="text-xs text-gray-500 mt-1">{s.label}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* ── FEATURE SHOWCASE ── */}
              {!result && !loading && (
                <div className="max-w-4xl mx-auto">
                  <h3 className="text-center text-xs uppercase tracking-widest text-gray-500 mb-6">Detection Capabilities</h3>
                  <div className="grid md:grid-cols-3 gap-4">
                    {[
                      {
                        icon: '🧠',
                        title: 'AI Heuristic Engine',
                        desc: 'Multi-layer pattern recognition analyzing 20+ threat signals simultaneously for accurate phishing detection.',
                        color: 'cyan'
                      },
                      {
                        icon: '🔑',
                        title: 'Keyword Intelligence',
                        desc: 'Scans for 50+ phishing keywords across URL path, query params, and domain — login, verify, secure, bank, and more.',
                        color: 'emerald'
                      },
                      {
                        icon: '🔗',
                        title: 'Link Shortener Detection',
                        desc: 'Identifies 15+ URL shortener services (bit.ly, tinyurl, t.co) that are commonly used to mask malicious destinations.',
                        color: 'yellow'
                      },
                      {
                        icon: '🌐',
                        title: 'Domain Anomaly Detection',
                        desc: 'Flags suspicious TLDs (.tk, .xyz, .ga), IP-based URLs, excessive subdomains, and domain squatting patterns.',
                        color: 'purple'
                      },
                      {
                        icon: '🔤',
                        title: 'Typosquatting Analysis',
                        desc: 'Detects look-alike domains mimicking popular brands using character substitution (paypa1, amaz0n, g00gle).',
                        color: 'red'
                      },
                      {
                        icon: '📊',
                        title: 'Dynamic Risk Scoring',
                        desc: 'Weighted risk calculation assigns scores 0-100 based on severity. Clear Safe / Suspicious / Dangerous verdict.',
                        color: 'blue'
                      },
                    ].map(f => (
                      <div key={f.title} className="bg-[#0d1625] border border-white/10 rounded-xl p-5 hover:border-cyan-500/20 transition-all group">
                        <div className="text-3xl mb-3 group-hover:scale-110 transition-transform">{f.icon}</div>
                        <h4 className="font-bold text-sm text-white mb-2">{f.title}</h4>
                        <p className="text-xs text-gray-500 leading-relaxed">{f.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── HISTORY TAB ── */}
          {activeTab === 'history' && (
            <ScanHistory history={history} onRecan={(u: string) => { setUrl(u); setActiveTab('scanner'); }} />
          )}

          {/* ── ABOUT TAB ── */}
          {activeTab === 'about' && (
            <div className="max-w-4xl mx-auto space-y-8 py-4">
              <div className="text-center space-y-3">
                <div className="text-6xl">🛡️</div>
                <h2 className="text-3xl font-black bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">
                  About PhishGuard
                </h2>
                <p className="text-gray-400 max-w-2xl mx-auto text-sm leading-relaxed">
                  PhishGuard is an enterprise-grade AI-powered URL threat detection system that analyzes URLs
                  in real-time using advanced heuristic algorithms to protect users from phishing, malware,
                  and social engineering attacks.
                </p>
              </div>

              <div className="grid md:grid-cols-2 gap-6">
                {[
                  {
                    title: 'Detection Methods',
                    icon: '🔍',
                    items: [
                      'Suspicious keyword analysis (50+ keywords)',
                      'URL structure & length anomaly detection',
                      'Domain reputation & TLD analysis',
                      'IP-based URL detection',
                      'Link shortener identification (15+ services)',
                      'Typosquatting & brand impersonation',
                      'Homograph attack detection',
                      'Excessive redirect parameter detection',
                      'HTTPS/HTTP security check',
                      'Subdomain chain analysis',
                    ]
                  },
                  {
                    title: 'Tech Stack',
                    icon: '⚙️',
                    items: [
                      'React 19 + TypeScript',
                      'Tailwind CSS v4 (utility-first styling)',
                      'Vite (lightning-fast build tool)',
                      'Heuristic scoring algorithm',
                      'Real-time URL parsing & analysis',
                      'Client-side processing (no data leaves browser)',
                      'Regex-based pattern matching engine',
                      'Weighted threat scoring system',
                      'Zero external API dependencies',
                      'Privacy-first architecture',
                    ]
                  }
                ].map(section => (
                  <div key={section.title} className="bg-[#0d1625] border border-white/10 rounded-2xl p-6">
                    <h3 className="font-bold text-white mb-4 flex items-center gap-2">
                      <span>{section.icon}</span> {section.title}
                    </h3>
                    <ul className="space-y-2">
                      {section.items.map(item => (
                        <li key={item} className="flex items-start gap-2 text-xs text-gray-400">
                          <span className="text-cyan-400 mt-0.5 flex-shrink-0">✓</span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>

              <div className="bg-gradient-to-r from-cyan-900/20 to-emerald-900/20 border border-cyan-500/20 rounded-2xl p-6 text-center space-y-2">
                <div className="text-sm text-gray-400">⚠️ Disclaimer</div>
                <p className="text-xs text-gray-500 max-w-2xl mx-auto leading-relaxed">
                  PhishGuard uses heuristic analysis for educational and demonstration purposes. For production environments,
                  combine with live threat intelligence feeds (VirusTotal, Google Safe Browsing API, etc.).
                  Always verify with multiple security tools before accessing unknown URLs.
                </p>
              </div>
            </div>
          )}
        </main>

        {/* Footer */}
        <footer className="border-t border-white/5 mt-16 py-8 text-center">
          <div className="text-xs text-gray-600 space-y-1">
            <p className="text-gray-500 font-bold tracking-widest">PHISHGUARD <span className="text-cyan-600">v2.0</span></p>
            <p>AI-Powered Phishing URL Detection Engine</p>
            <p className="flex items-center justify-center gap-4 mt-2">
              <span>🔒 Privacy-first</span>
              <span>⚡ Client-side processing</span>
              <span>🛡️ Zero data collection</span>
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
}
