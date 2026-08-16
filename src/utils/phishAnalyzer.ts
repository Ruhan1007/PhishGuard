export interface Finding {
  id: string;
  label: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  weight: number;
  triggered: boolean;
}

export interface Indicator {
  name: string;
  value: string;
  status: 'danger' | 'warning' | 'safe' | 'info';
  icon: string;
}

export interface AnalysisResult {
  riskScore: number;
  verdict: string;
  findings: Finding[];
  indicators: Indicator[];
  urlParts: Record<string, string>;
  recommendations: string[];
  analysisTime: number;
}

// ── Threat data ──────────────────────────────────────────────────────────────

const PHISHING_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'secure', 'security', 'update', 'confirm', 'account', 'password',
  'bank', 'banking', 'paypal', 'payment', 'billing', 'checkout',
  'alert', 'warning', 'suspended', 'locked', 'validate', 'restore',
  'recover', 'reset', 'credential', 'authenticate', 'webscr',
  'cmd=login', 'ebayisapi', 'dispatch', 'click', 'redirect',
];

const HIGH_RISK_KEYWORDS = [
  'free-gift', 'winner', 'prize', 'claim-now', 'urgent', 'limited-time',
  'act-now', 'expire', 'immediately', 'lottery', 'lucky', 'jackpot',
];

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
  '.click', '.link', '.gdn', '.stream', '.download', '.onion',
  '.loan', '.men', '.racing', '.accountant', '.trade', '.cricket',
];

// Reference for future reputation scoring
const _SAFE_TLDS = ['.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.io'];
void _SAFE_TLDS;

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'short.link', 'rebrand.ly', 'cutt.ly',
  'rb.gy', 'tiny.cc', 'shorte.st', 'linktr.ee', 'bl.ink',
  'tr.im', 'snip.ly', 'po.st', 'mcaf.ee', 'gg.gg',
];

const TRUSTED_DOMAINS = [
  'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
  'apple.com', 'github.com', 'linkedin.com', 'twitter.com',
  'youtube.com', 'instagram.com', 'wikipedia.org', 'reddit.com',
  'stackoverflow.com', 'netflix.com', 'spotify.com', 'dropbox.com',
  'paypal.com', 'ebay.com', 'adobe.com', 'cloudflare.com',
];

const BRAND_NAMES = [
  'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
  'netflix', 'ebay', 'instagram', 'twitter', 'linkedin', 'dropbox',
  'chase', 'wellsfargo', 'citibank', 'bankofamerica', 'hsbc',
  'fedex', 'ups', 'dhl', 'usps', 'irs', 'covid', 'whatsapp',
];

// ── URL normalizer ────────────────────────────────────────────────────────────

function normalizeURL(raw: string): string {
  let u = raw.trim();
  if (!u.startsWith('http://') && !u.startsWith('https://') && !u.startsWith('ftp://')) {
    u = 'https://' + u;
  }
  return u;
}

// ── Parse URL safely ──────────────────────────────────────────────────────────

function parseURL(raw: string): { parsed: URL | null; normalized: string } {
  const normalized = normalizeURL(raw);
  try {
    return { parsed: new URL(normalized), normalized };
  } catch {
    return { parsed: null, normalized };
  }
}

// ── Main analyzer ─────────────────────────────────────────────────────────────

export function analyzeURL(raw: string): AnalysisResult {
  const start = performance.now();
  const { parsed, normalized } = parseURL(raw);

  const hostname = parsed?.hostname?.toLowerCase() ?? raw.toLowerCase();
  const pathname = parsed?.pathname?.toLowerCase() ?? '';
  const search = parsed?.search?.toLowerCase() ?? '';
  const protocol = parsed?.protocol ?? '';
  const fullURL = normalized.toLowerCase();
  const tld = '.' + hostname.split('.').slice(-1)[0];
  const registrable = hostname.split('.').slice(-2).join('.');
  const subdomainParts = hostname.split('.').slice(0, -2);
  const paramCount = search ? search.split('&').length : 0;

  // Build URL parts for display
  const urlParts: Record<string, string> = {
    protocol: protocol || 'unknown',
    domain: hostname,
    path: pathname || '/',
    query: search || '',
    tld,
    subdomains: subdomainParts.join('.') || 'none',
    'param count': String(paramCount),
    length: `${raw.length} chars`,
  };

  // ── Check if it's a trusted domain (bonus: early return safe) ────────────
  const isTrusted = TRUSTED_DOMAINS.some(d => registrable === d || hostname === d);

  // ── All findings ──────────────────────────────────────────────────────────
  const findings: Finding[] = [];

  // 1. Phishing keywords in URL
  const foundKeywords = PHISHING_KEYWORDS.filter(kw => fullURL.includes(kw));
  findings.push({
    id: 'phishing_keywords',
    label: 'Phishing Keywords',
    description: foundKeywords.length
      ? `Found suspicious keywords: ${foundKeywords.slice(0, 4).join(', ')}`
      : 'No phishing keywords detected in URL',
    severity: foundKeywords.length > 3 ? 'critical' : foundKeywords.length > 1 ? 'high' : foundKeywords.length === 1 ? 'medium' : 'safe',
    weight: Math.min(foundKeywords.length * 8, 30),
    triggered: foundKeywords.length > 0,
  });

  // 2. High-risk keywords
  const foundHighRisk = HIGH_RISK_KEYWORDS.filter(kw => fullURL.includes(kw));
  findings.push({
    id: 'high_risk_keywords',
    label: 'High-Risk Lure Keywords',
    description: foundHighRisk.length
      ? `Lure keywords: ${foundHighRisk.join(', ')}`
      : 'No lure keywords detected',
    severity: foundHighRisk.length > 0 ? 'critical' : 'safe',
    weight: foundHighRisk.length * 15,
    triggered: foundHighRisk.length > 0,
  });

  // 3. URL shortener
  const isShortener = URL_SHORTENERS.some(s => hostname.includes(s));
  findings.push({
    id: 'url_shortener',
    label: 'URL Shortener',
    description: isShortener
      ? `URL uses a link shortener (${hostname}) which hides the real destination`
      : 'URL is not using a link shortening service',
    severity: isShortener ? 'high' : 'safe',
    weight: isShortener ? 20 : 0,
    triggered: isShortener,
  });

  // 4. Suspicious TLD
  const isSuspiciousTLD = SUSPICIOUS_TLDS.some(t => hostname.endsWith(t));
  findings.push({
    id: 'suspicious_tld',
    label: 'Suspicious TLD',
    description: isSuspiciousTLD
      ? `The domain uses a high-risk TLD: ${tld}`
      : `TLD "${tld}" is within normal range`,
    severity: isSuspiciousTLD ? 'high' : 'safe',
    weight: isSuspiciousTLD ? 20 : 0,
    triggered: isSuspiciousTLD,
  });

  // 5. IP-based URL
  const isIPURL = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  findings.push({
    id: 'ip_url',
    label: 'IP Address URL',
    description: isIPURL
      ? `URL uses a raw IP address (${hostname}) instead of a domain name — a common phishing tactic`
      : 'URL uses a proper domain name',
    severity: isIPURL ? 'critical' : 'safe',
    weight: isIPURL ? 30 : 0,
    triggered: isIPURL,
  });

  // 6. HTTP (no HTTPS)
  const isHTTP = protocol === 'http:';
  findings.push({
    id: 'no_https',
    label: 'Insecure Protocol (HTTP)',
    description: isHTTP
      ? 'URL uses insecure HTTP — sensitive data is not encrypted'
      : 'URL uses HTTPS encryption',
    severity: isHTTP ? 'medium' : 'safe',
    weight: isHTTP ? 10 : 0,
    triggered: isHTTP,
  });

  // 7. Excessive subdomains
  const subdomainCount = subdomainParts.filter(s => s !== 'www').length;
  findings.push({
    id: 'excess_subdomains',
    label: 'Excessive Subdomains',
    description: subdomainCount > 2
      ? `${subdomainCount} subdomain levels detected — used to mimic trusted domains (e.g., paypal.secure.evil.com)`
      : 'Normal subdomain structure',
    severity: subdomainCount > 3 ? 'critical' : subdomainCount > 2 ? 'high' : 'safe',
    weight: Math.min(subdomainCount * 7, 25),
    triggered: subdomainCount > 2,
  });

  // 8. Brand name in domain (typosquatting)
  const brandInDomain = BRAND_NAMES.filter(b => hostname.includes(b) && !TRUSTED_DOMAINS.some(td => hostname === td || registrable === td));
  findings.push({
    id: 'brand_impersonation',
    label: 'Brand Impersonation',
    description: brandInDomain.length && !isTrusted
      ? `Domain impersonates known brand(s): ${brandInDomain.join(', ')}`
      : 'No brand impersonation detected',
    severity: brandInDomain.length && !isTrusted ? 'critical' : 'safe',
    weight: brandInDomain.length && !isTrusted ? 25 : 0,
    triggered: brandInDomain.length > 0 && !isTrusted,
  });

  // 9. Long URL
  const urlLength = raw.length;
  findings.push({
    id: 'long_url',
    label: 'Abnormal URL Length',
    description: urlLength > 100
      ? `URL is very long (${urlLength} chars) — attackers use this to hide malicious segments`
      : urlLength > 75
      ? `URL is moderately long (${urlLength} chars)`
      : `URL length is normal (${urlLength} chars)`,
    severity: urlLength > 100 ? 'medium' : urlLength > 75 ? 'low' : 'safe',
    weight: urlLength > 100 ? 12 : urlLength > 75 ? 5 : 0,
    triggered: urlLength > 75,
  });

  // 10. Typosquatting (leetspeak: 0→o, 1→l/i, 3→e, 4→a)
  const leetPattern = /[0-9]/.test(hostname.replace(/\d+\.\d+\.\d+\.\d+/, ''));
  const leet = leetPattern && !isIPURL;
  findings.push({
    id: 'typosquatting',
    label: 'Typosquatting / Leetspeak',
    description: leet
      ? `Domain contains digit substitutions (e.g., "paypa1", "amaz0n") that mimic real brands`
      : 'No leetspeak character substitution detected',
    severity: leet ? 'high' : 'safe',
    weight: leet ? 18 : 0,
    triggered: leet,
  });

  // 11. @ symbol in URL (credential harvesting)
  const hasAt = fullURL.includes('@');
  findings.push({
    id: 'at_symbol',
    label: '@ Symbol in URL',
    description: hasAt
      ? 'URL contains "@" symbol — browsers ignore everything before it, used to deceive users'
      : 'No @ symbol deception detected',
    severity: hasAt ? 'critical' : 'safe',
    weight: hasAt ? 30 : 0,
    triggered: hasAt,
  });

  // 12. Double slashes in path (path manipulation)
  const doubleSlash = pathname.includes('//');
  findings.push({
    id: 'double_slash',
    label: 'Path Manipulation',
    description: doubleSlash
      ? 'URL contains double slashes in path — possible URL manipulation/obfuscation'
      : 'URL path structure is normal',
    severity: doubleSlash ? 'medium' : 'safe',
    weight: doubleSlash ? 10 : 0,
    triggered: doubleSlash,
  });

  // 13. Redirect parameters
  const redirectParams = ['redirect', 'url', 'next', 'return', 'dest', 'destination', 'forward', 'goto'];
  const hasRedirect = redirectParams.some(p => search.includes(`${p}=`));
  findings.push({
    id: 'redirect_param',
    label: 'Open Redirect Parameter',
    description: hasRedirect
      ? 'URL contains redirect parameters that can forward users to malicious sites'
      : 'No suspicious redirect parameters found',
    severity: hasRedirect ? 'high' : 'safe',
    weight: hasRedirect ? 15 : 0,
    triggered: hasRedirect,
  });

  // 14. Punycode / IDN homograph
  const hasPunycode = hostname.includes('xn--');
  findings.push({
    id: 'punycode',
    label: 'IDN Homograph Attack',
    description: hasPunycode
      ? 'Domain uses punycode/international characters to visually impersonate trusted domains'
      : 'No internationalized domain name attack detected',
    severity: hasPunycode ? 'critical' : 'safe',
    weight: hasPunycode ? 30 : 0,
    triggered: hasPunycode,
  });

  // 15. Trusted domain bonus (reduce score)
  findings.push({
    id: 'trusted_domain',
    label: 'Trusted Domain',
    description: isTrusted
      ? `"${registrable}" is a well-known trusted domain`
      : 'Domain is not in the trusted domain whitelist',
    severity: isTrusted ? 'safe' : 'info' as 'safe',
    weight: isTrusted ? -50 : 0,
    triggered: !isTrusted,
  });

  // ── Score calculation ─────────────────────────────────────────────────────
  const rawScore = findings.reduce((acc, f) => acc + (f.triggered ? f.weight : 0), 0);
  const riskScore = Math.min(100, Math.max(0, rawScore));

  // ── Verdict ───────────────────────────────────────────────────────────────
  let verdict: string;
  if (riskScore >= 75) verdict = '🚨 HIGH RISK — Likely Phishing';
  else if (riskScore >= 45) verdict = '⚠️ SUSPICIOUS — Proceed with Caution';
  else if (riskScore >= 20) verdict = '🟡 LOW RISK — Some Concerns Found';
  else verdict = '✅ SAFE — No Significant Threats Detected';

  // ── Indicators ────────────────────────────────────────────────────────────
  const indicators: Indicator[] = [
    {
      name: 'HTTPS',
      value: protocol === 'https:' ? 'Encrypted' : 'Unencrypted',
      status: protocol === 'https:' ? 'safe' : 'danger',
      icon: protocol === 'https:' ? '🔒' : '🔓',
    },
    {
      name: 'Domain Age',
      value: isSuspiciousTLD ? 'High-risk TLD' : isTrusted ? 'Established' : 'Unknown',
      status: isSuspiciousTLD ? 'danger' : isTrusted ? 'safe' : 'warning',
      icon: '📅',
    },
    {
      name: 'Shortener',
      value: isShortener ? 'Detected' : 'Not Found',
      status: isShortener ? 'danger' : 'safe',
      icon: '🔗',
    },
    {
      name: 'IP Address',
      value: isIPURL ? 'Yes' : 'No',
      status: isIPURL ? 'danger' : 'safe',
      icon: '🖥️',
    },
    {
      name: 'Brand Spoof',
      value: brandInDomain.length && !isTrusted ? brandInDomain[0].toUpperCase() : 'None',
      status: brandInDomain.length && !isTrusted ? 'danger' : 'safe',
      icon: '🎭',
    },
    {
      name: 'Trust Level',
      value: isTrusted ? 'Trusted' : riskScore >= 75 ? 'Untrusted' : 'Unknown',
      status: isTrusted ? 'safe' : riskScore >= 75 ? 'danger' : 'warning',
      icon: isTrusted ? '✅' : '❓',
    },
    {
      name: 'URL Length',
      value: urlLength > 100 ? 'Very Long' : urlLength > 75 ? 'Long' : 'Normal',
      status: urlLength > 100 ? 'danger' : urlLength > 75 ? 'warning' : 'safe',
      icon: '📏',
    },
    {
      name: 'Subdomains',
      value: `${subdomainCount} levels`,
      status: subdomainCount > 2 ? 'danger' : subdomainCount > 1 ? 'warning' : 'safe',
      icon: '🌐',
    },
  ];

  // ── Recommendations ───────────────────────────────────────────────────────
  const recommendations: string[] = [];
  if (riskScore >= 75) {
    recommendations.push('Do NOT click this link or enter any credentials.');
    recommendations.push('Report this URL to your IT/security team immediately.');
    recommendations.push('Block this domain in your security tools.');
    recommendations.push('Warn others who may have received this link.');
  }
  if (isHTTP) recommendations.push('Never enter sensitive info on HTTP sites — always look for HTTPS.');
  if (isShortener) recommendations.push('Expand shortened URLs using tools like checkshorturl.com before clicking.');
  if (brandInDomain.length && !isTrusted) recommendations.push(`Verify the real URL of "${brandInDomain[0]}" before entering credentials.`);
  if (isSuspiciousTLD) recommendations.push(`Be extra cautious with domains using the "${tld}" TLD — they are commonly abused.`);
  if (hasRedirect) recommendations.push('URLs with redirect parameters can forward you to different malicious sites.');
  if (leet) recommendations.push('Check for character substitutions: "0" for "o", "1" for "l", "3" for "e", etc.');
  if (subdomainCount > 2) recommendations.push('Always check the actual registered domain (last two parts before the TLD).');
  if (hasPunycode) recommendations.push('IDN homograph attacks use look-alike Unicode characters — verify the domain carefully.');
  if (recommendations.length === 0) {
    recommendations.push('Always verify URLs before clicking, even if they appear safe.');
    recommendations.push('Keep your browser and security software up to date.');
    recommendations.push('Enable multi-factor authentication on all important accounts.');
    recommendations.push('Use a password manager to avoid being fooled by look-alike sites.');
  }

  return {
    riskScore,
    verdict,
    findings: findings.filter(f => f.id !== 'trusted_domain' || isTrusted),
    indicators,
    urlParts,
    recommendations,
    analysisTime: Math.round(performance.now() - start),
  };
}
