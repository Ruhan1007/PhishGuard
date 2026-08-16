/**
 * PhishGuard — script.js
 * AI Phishing URL Detector — Standalone Vanilla JS Implementation
 * ================================================================
 */

'use strict';

// ════════════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE DATA
// ════════════════════════════════════════════════════════════════════

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

const QUICK_TESTS = [
  { label: '⚠️ Suspicious', url: 'http://paypa1-secure-login.xyz/verify?user=admin' },
  { label: '🔗 Shortened',  url: 'https://bit.ly/3xK9mP2' },
  { label: '✅ Safe',        url: 'https://google.com' },
  { label: '🚨 Phishing',   url: 'http://secure-amazon-account-update.tk/login?redirect=payment' },
];

// ════════════════════════════════════════════════════════════════════
// CORE ANALYZER
// ════════════════════════════════════════════════════════════════════

function normalizeURL(raw) {
  let u = raw.trim();
  if (!u.startsWith('http://') && !u.startsWith('https://') && !u.startsWith('ftp://')) {
    u = 'https://' + u;
  }
  return u;
}

function parseURL(raw) {
  const normalized = normalizeURL(raw);
  try { return { parsed: new URL(normalized), normalized }; }
  catch { return { parsed: null, normalized }; }
}

function analyzeURL(raw) {
  const t0 = performance.now();
  const { parsed, normalized } = parseURL(raw);

  const hostname  = (parsed?.hostname ?? raw).toLowerCase();
  const pathname  = (parsed?.pathname ?? '').toLowerCase();
  const search    = (parsed?.search ?? '').toLowerCase();
  const protocol  = parsed?.protocol ?? '';
  const fullURL   = normalized.toLowerCase();
  const tld       = '.' + hostname.split('.').slice(-1)[0];
  const registrable = hostname.split('.').slice(-2).join('.');
  const subdomainParts = hostname.split('.').slice(0, -2).filter(p => p !== 'www');
  const paramCount = search ? search.split('&').length : 0;

  const isTrusted = TRUSTED_DOMAINS.some(d => registrable === d || hostname === d);

  const findings = [];

  // 1. Phishing keywords
  const foundKw = PHISHING_KEYWORDS.filter(k => fullURL.includes(k));
  findings.push({
    id: 'phishing_keywords',
    label: 'Phishing Keywords',
    description: foundKw.length
      ? `Found: ${foundKw.slice(0, 4).join(', ')}`
      : 'No phishing keywords detected',
    severity: foundKw.length > 3 ? 'critical' : foundKw.length > 1 ? 'high' : foundKw.length === 1 ? 'medium' : 'safe',
    weight: Math.min(foundKw.length * 8, 30),
    triggered: foundKw.length > 0,
  });

  // 2. High-risk lure keywords
  const foundHR = HIGH_RISK_KEYWORDS.filter(k => fullURL.includes(k));
  findings.push({
    id: 'high_risk_keywords',
    label: 'High-Risk Lure Keywords',
    description: foundHR.length ? `Lure keywords: ${foundHR.join(', ')}` : 'No lure keywords detected',
    severity: foundHR.length > 0 ? 'critical' : 'safe',
    weight: foundHR.length * 15,
    triggered: foundHR.length > 0,
  });

  // 3. URL shortener
  const isShortener = URL_SHORTENERS.some(s => hostname.includes(s));
  findings.push({
    id: 'url_shortener',
    label: 'URL Shortener Detected',
    description: isShortener
      ? `Uses link shortener (${hostname}) which hides real destination`
      : 'Not using a link shortener',
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
      ? `High-risk TLD detected: ${tld}`
      : `TLD "${tld}" within normal range`,
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
      ? `Raw IP address used (${hostname}) — common phishing tactic`
      : 'URL uses a proper domain name',
    severity: isIPURL ? 'critical' : 'safe',
    weight: isIPURL ? 30 : 0,
    triggered: isIPURL,
  });

  // 6. HTTP
  const isHTTP = protocol === 'http:';
  findings.push({
    id: 'no_https',
    label: 'Insecure Protocol (HTTP)',
    description: isHTTP ? 'HTTP used — data is not encrypted' : 'HTTPS encryption detected',
    severity: isHTTP ? 'medium' : 'safe',
    weight: isHTTP ? 10 : 0,
    triggered: isHTTP,
  });

  // 7. Excessive subdomains
  const subCount = subdomainParts.length;
  findings.push({
    id: 'excess_subdomains',
    label: 'Excessive Subdomains',
    description: subCount > 2
      ? `${subCount} subdomain levels — mimics trusted domains (e.g. paypal.secure.evil.com)`
      : 'Normal subdomain structure',
    severity: subCount > 3 ? 'critical' : subCount > 2 ? 'high' : 'safe',
    weight: Math.min(subCount * 7, 25),
    triggered: subCount > 2,
  });

  // 8. Brand impersonation
  const brandMatches = BRAND_NAMES.filter(b => hostname.includes(b) && !TRUSTED_DOMAINS.some(td => hostname === td || registrable === td));
  findings.push({
    id: 'brand_impersonation',
    label: 'Brand Impersonation',
    description: brandMatches.length && !isTrusted
      ? `Domain impersonates: ${brandMatches.join(', ')}`
      : 'No brand impersonation detected',
    severity: brandMatches.length && !isTrusted ? 'critical' : 'safe',
    weight: brandMatches.length && !isTrusted ? 25 : 0,
    triggered: brandMatches.length > 0 && !isTrusted,
  });

  // 9. URL length
  const urlLen = raw.length;
  findings.push({
    id: 'long_url',
    label: 'Abnormal URL Length',
    description: urlLen > 100 ? `Very long URL (${urlLen} chars)` : urlLen > 75 ? `Long URL (${urlLen} chars)` : `Normal length (${urlLen} chars)`,
    severity: urlLen > 100 ? 'medium' : urlLen > 75 ? 'low' : 'safe',
    weight: urlLen > 100 ? 12 : urlLen > 75 ? 5 : 0,
    triggered: urlLen > 75,
  });

  // 10. Typosquatting / leetspeak
  const leet = /[0-9]/.test(hostname.replace(/\d+\.\d+\.\d+\.\d+/, '')) && !isIPURL;
  findings.push({
    id: 'typosquatting',
    label: 'Typosquatting / Leetspeak',
    description: leet ? 'Digit substitutions detected (paypa1, amaz0n, g00gle)' : 'No character substitution detected',
    severity: leet ? 'high' : 'safe',
    weight: leet ? 18 : 0,
    triggered: leet,
  });

  // 11. @ symbol
  const hasAt = fullURL.includes('@');
  findings.push({
    id: 'at_symbol',
    label: '@ Symbol in URL',
    description: hasAt ? '"@" detected — browsers ignore everything before it' : 'No @ symbol deception',
    severity: hasAt ? 'critical' : 'safe',
    weight: hasAt ? 30 : 0,
    triggered: hasAt,
  });

  // 12. Double slashes
  const doubleSlash = pathname.includes('//');
  findings.push({
    id: 'double_slash',
    label: 'Path Manipulation',
    description: doubleSlash ? 'Double slashes in path — URL obfuscation' : 'URL path structure is normal',
    severity: doubleSlash ? 'medium' : 'safe',
    weight: doubleSlash ? 10 : 0,
    triggered: doubleSlash,
  });

  // 13. Redirect parameters
  const redirectParams = ['redirect=', 'url=', 'next=', 'return=', 'dest=', 'forward=', 'goto='];
  const hasRedirect = redirectParams.some(p => search.includes(p));
  findings.push({
    id: 'redirect_param',
    label: 'Open Redirect Parameter',
    description: hasRedirect ? 'Redirect parameters can forward to malicious sites' : 'No suspicious redirect parameters',
    severity: hasRedirect ? 'high' : 'safe',
    weight: hasRedirect ? 15 : 0,
    triggered: hasRedirect,
  });

  // 14. Punycode
  const hasPunycode = hostname.includes('xn--');
  findings.push({
    id: 'punycode',
    label: 'IDN Homograph Attack',
    description: hasPunycode ? 'Punycode/international chars mimic trusted domains' : 'No IDN homograph attack detected',
    severity: hasPunycode ? 'critical' : 'safe',
    weight: hasPunycode ? 30 : 0,
    triggered: hasPunycode,
  });

  // Score
  const rawScore = findings.reduce((a, f) => a + (f.triggered ? f.weight : 0), 0);
  const isTrustedBonus = isTrusted ? 50 : 0;
  const riskScore = Math.min(100, Math.max(0, rawScore - isTrustedBonus));

  let verdict;
  if (riskScore >= 75) verdict = '🚨 HIGH RISK — Likely Phishing';
  else if (riskScore >= 45) verdict = '⚠️ SUSPICIOUS — Proceed with Caution';
  else if (riskScore >= 20) verdict = '🟡 LOW RISK — Some Concerns Found';
  else verdict = '✅ SAFE — No Significant Threats Detected';

  const indicators = [
    { name: 'HTTPS',     value: protocol === 'https:' ? 'Encrypted'   : 'Unencrypted', status: protocol === 'https:' ? 'safe' : 'danger', icon: protocol === 'https:' ? '🔒' : '🔓' },
    { name: 'Shortener', value: isShortener ? 'Detected'   : 'Not Found',  status: isShortener ? 'danger' : 'safe', icon: '🔗' },
    { name: 'IP URL',    value: isIPURL ? 'Yes'         : 'No',           status: isIPURL ? 'danger' : 'safe', icon: '🖥️' },
    { name: 'Brand Spoof', value: brandMatches.length && !isTrusted ? brandMatches[0].toUpperCase() : 'None', status: brandMatches.length && !isTrusted ? 'danger' : 'safe', icon: '🎭' },
    { name: 'Trust',     value: isTrusted ? 'Trusted'    : riskScore >= 75 ? 'Untrusted' : 'Unknown', status: isTrusted ? 'safe' : riskScore >= 75 ? 'danger' : 'warning', icon: isTrusted ? '✅' : '❓' },
    { name: 'TLD Risk',  value: isSuspiciousTLD ? 'HIGH'       : 'Normal',       status: isSuspiciousTLD ? 'danger' : 'safe', icon: '🌐' },
    { name: 'URL Len',   value: urlLen > 100 ? 'Very Long'  : urlLen > 75 ? 'Long' : 'Normal', status: urlLen > 100 ? 'danger' : urlLen > 75 ? 'warning' : 'safe', icon: '📏' },
    { name: 'Subdomains', value: `${subCount} levels`, status: subCount > 2 ? 'danger' : subCount > 1 ? 'warning' : 'safe', icon: '🌐' },
  ];

  const urlParts = {
    protocol: protocol || 'unknown',
    domain: hostname,
    path: pathname || '/',
    query: search || '',
    tld,
    subdomains: subdomainParts.join('.') || 'none',
    'params': String(paramCount),
    length: `${raw.length} chars`,
  };

  // Recommendations
  const recs = [];
  if (riskScore >= 75) {
    recs.push('Do NOT click this link or enter credentials.');
    recs.push('Report to your IT/security team immediately.');
    recs.push('Block this domain in your security tools.');
  }
  if (isHTTP) recs.push('Never enter sensitive info on HTTP sites.');
  if (isShortener) recs.push('Expand shortened URLs with checkshorturl.com first.');
  if (brandMatches.length && !isTrusted) recs.push(`Verify the official "${brandMatches[0]}" website separately.`);
  if (isSuspiciousTLD) recs.push(`Be extra cautious with "${tld}" TLD — commonly abused.`);
  if (hasRedirect) recs.push('Open redirect parameters can forward you to malicious sites.');
  if (leet) recs.push('Check for char substitutions: "0"→"o", "1"→"l", "3"→"e".');
  if (subCount > 2) recs.push('Check the actual registered domain (last two parts before TLD).');
  if (recs.length === 0) {
    recs.push('Always verify URLs before clicking, even if they appear safe.');
    recs.push('Enable multi-factor authentication on all accounts.');
    recs.push('Use a password manager to avoid look-alike site tricks.');
    recs.push('Keep browser and security software up to date.');
  }

  return {
    riskScore, verdict, findings, indicators, urlParts, recommendations: recs,
    analysisTime: Math.round(performance.now() - t0),
    isTrusted, hostname, isSuspiciousTLD, isShortener, isHTTP,
  };
}

// ════════════════════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════════════════════

const state = {
  currentURL: '',
  result: null,
  history: [],
  activeTab: 'scanner',
};

// ════════════════════════════════════════════════════════════════════
// RENDER HELPERS
// ════════════════════════════════════════════════════════════════════

function severityClass(s) {
  return { critical: 'critical', high: 'high', medium: 'medium', low: 'low', safe: 'safe-item', info: 'safe-item' }[s] ?? 'safe-item';
}
function indicatorClass(s) {
  return { danger: 'danger', warning: 'warning', safe: 'safe-ic', info: 'info-ic' }[s] ?? 'info-ic';
}
function riskClass(score) {
  return score >= 75 ? 'danger' : score >= 45 ? 'warning' : 'safe';
}
function riskIcon(score) {
  return score >= 75 ? '🚨' : score >= 45 ? '⚠️' : '✅';
}
function riskColorCSS(score) {
  return score >= 75 ? 'var(--red)' : score >= 45 ? 'var(--yellow)' : 'var(--emerald)';
}

function buildRingMeter(score) {
  const r = 42, circ = 2 * Math.PI * r;
  const offset = ((100 - score) / 100) * circ;
  const color = riskColorCSS(score);
  const label = score >= 75 ? 'HIGH' : score >= 45 ? 'MED' : 'LOW';
  return `
    <div class="risk-meter">
      <svg width="100" height="100" viewBox="0 0 100 100" style="transform:rotate(-90deg)">
        <circle cx="50" cy="50" r="${r}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="8"/>
        <circle cx="50" cy="50" r="${r}" fill="none" stroke="${color}" stroke-width="8"
          stroke-linecap="round"
          stroke-dasharray="${circ}"
          stroke-dashoffset="${offset}"
          style="transition:stroke-dashoffset 1s ease;filter:drop-shadow(0 0 6px ${color})"
        />
        <text x="50" y="50" dominant-baseline="central" text-anchor="middle"
          style="fill:${color};font-size:20px;font-weight:900;font-family:var(--font-mono);transform:rotate(90deg);transform-origin:50% 50%">
          ${score}
        </text>
        <text x="50" y="63" dominant-baseline="central" text-anchor="middle"
          style="fill:${color};font-size:9px;font-weight:700;font-family:var(--font-mono);letter-spacing:0.1em;transform:rotate(90deg);transform-origin:50% 50%">
          ${label}
        </text>
      </svg>
      <div class="meter-label" style="color:${color}">${label} RISK</div>
    </div>`;
}

function buildFindingsHTML(findings) {
  const triggered = findings.filter(f => f.triggered);
  const safe = findings.filter(f => !f.triggered);
  const all = [...triggered, ...safe];
  return all.map(f => {
    const cls = severityClass(f.severity);
    const sev = f.triggered ? f.severity : 'safe';
    const icon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', safe: '🟢', info: '🔵' }[sev] ?? '🟢';
    const ptsBar = f.triggered && f.weight > 0 ? `
      <div class="weight-bar">
        <div class="weight-track"><div class="weight-fill" style="width:${Math.min((f.weight / 30) * 100, 100)}%"></div></div>
        <span class="weight-pts">+${f.weight}pts</span>
      </div>` : '';
    return `
      <div class="finding-item ${cls}">
        <div class="finding-header">
          <div class="finding-name">${icon} ${f.label}</div>
          <span class="severity-badge">${sev}</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${ptsBar}
      </div>`;
  }).join('');
}

function buildIndicatorsHTML(indicators) {
  return indicators.map(ind => `
    <div class="indicator-card ${indicatorClass(ind.status)}">
      <div class="indicator-top">
        <span class="indicator-icon">${ind.icon}</span>
        <div class="indicator-dot"></div>
      </div>
      <div class="indicator-name">${ind.name}</div>
      <div class="indicator-value">${ind.value}</div>
    </div>`).join('');
}

function buildURLPartsHTML(urlParts) {
  return Object.entries(urlParts).map(([k, v]) => `
    <div class="url-part">
      <span class="part-key">${k}</span>
      <span class="part-val ${v ? '' : 'empty'}">${v || 'none'}</span>
    </div>`).join('');
}

function buildRecsHTML(recs) {
  return recs.map(r => `
    <div class="rec-item">
      <span class="rec-arrow">→</span>
      <span>${r}</span>
    </div>`).join('');
}

// ════════════════════════════════════════════════════════════════════
// RENDER RESULT
// ════════════════════════════════════════════════════════════════════

function renderResult(result, url) {
  const rc = riskClass(result.riskScore);
  const triggeredCount = result.findings.filter(f => f.triggered).length;

  return `
  <div class="result-section">
    <!-- Verdict Banner -->
    <div class="verdict-card ${rc}">
      <div class="verdict-emoji">${riskIcon(result.riskScore)}</div>
      <div class="verdict-info">
        <div class="verdict-label">Verdict</div>
        <div class="verdict-text">${result.verdict}</div>
        <div class="verdict-url">${url}</div>
        <div class="verdict-actions">
          <button class="action-btn" id="copyReportBtn">📋 Copy Report</button>
          <button class="action-btn" id="newScanBtn">🔄 New Scan</button>
          <button class="action-btn google" id="googleSBBtn">🔍 Google Safe Browsing ↗</button>
        </div>
      </div>
      ${buildRingMeter(result.riskScore)}
    </div>

    <!-- Two column: Threat Breakdown + URL Dissection -->
    <div class="two-col">
      <div class="card">
        <div class="card-title">
          <span>⚠️ Threat Breakdown</span>
          <span style="font-size:11px;color:var(--text-muted);font-weight:400">${triggeredCount}/${result.findings.length} triggered</span>
        </div>
        <div class="findings-list">${buildFindingsHTML(result.findings)}</div>
      </div>

      <div class="card">
        <div class="card-title"><span>🔬 URL Dissection</span></div>
        <div class="url-parts">${buildURLPartsHTML(result.urlParts)}</div>
      </div>
    </div>

    <!-- Indicators -->
    <div class="indicators-grid">${buildIndicatorsHTML(result.indicators)}</div>

    <!-- Recommendations -->
    <div class="card">
      <div class="card-title"><span>💡 Security Recommendations</span></div>
      <div class="recs-grid">${buildRecsHTML(result.recommendations)}</div>
    </div>

    <div style="text-align:center;font-size:11px;color:var(--text-muted);margin-top:12px">
      Analysis completed in ${result.analysisTime}ms · ${result.findings.length} checks performed
    </div>
  </div>`;
}

// ════════════════════════════════════════════════════════════════════
// RENDER HISTORY
// ════════════════════════════════════════════════════════════════════

function renderHistory() {
  const { history } = state;
  const historyContent = document.getElementById('historyContent');
  if (!historyContent) return;

  if (history.length === 0) {
    historyContent.innerHTML = `
      <div class="history-empty">
        <div class="e-icon">📋</div>
        <h3>No Scan History Yet</h3>
        <p>URLs you analyze will appear here for review.</p>
      </div>`;
    return;
  }

  const high = history.filter(h => h.score >= 75).length;
  const mid  = history.filter(h => h.score >= 45 && h.score < 75).length;
  const low  = history.filter(h => h.score < 45).length;
  const total = history.length;

  const items = history.map((entry, i) => {
    const rc = riskClass(entry.score);
    const hCls = rc === 'safe' ? 'safe-h' : rc;
    const hTime = entry.timestamp.toLocaleTimeString();
    return `
      <div class="history-item ${hCls}" data-index="${i}">
        <div class="h-emoji">${riskIcon(entry.score)}</div>
        <div class="h-info">
          <div class="h-url" title="${entry.url}">${entry.url}</div>
          <div class="h-meta">
            <span class="h-verdict">${entry.verdict}</span>
            <span class="h-time">${hTime}</span>
          </div>
        </div>
        <div class="h-score">${entry.score}</div>
        <button class="rescan-btn" data-url="${entry.url.replace(/"/g, '&quot;')}">Re-scan ↗</button>
      </div>`;
  }).join('');

  historyContent.innerHTML = `
    <div class="history-header">
      <div>
        <div class="history-title">Scan History</div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:4px">${total} URL${total !== 1 ? 's' : ''} analyzed this session</div>
      </div>
      <div class="history-badges">
        <div class="h-badge red">🚨 ${high} High Risk</div>
        <div class="h-badge yellow">⚠️ ${mid} Suspicious</div>
        <div class="h-badge green">✅ ${low} Safe</div>
      </div>
    </div>
    <div class="history-ratio">
      <div class="ratio-red" style="width:${(high/total)*100}%"></div>
      <div class="ratio-yellow" style="width:${(mid/total)*100}%"></div>
      <div class="ratio-green" style="width:${(low/total)*100}%"></div>
    </div>
    <div class="history-list">${items}</div>`;

  // Bind re-scan buttons
  historyContent.querySelectorAll('.rescan-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const url = btn.dataset.url;
      switchTab('scanner');
      document.getElementById('urlInput').value = url;
      state.currentURL = url;
    });
  });
}

// ════════════════════════════════════════════════════════════════════
// SCAN LOGIC
// ════════════════════════════════════════════════════════════════════

async function runScan() {
  const input = document.getElementById('urlInput');
  const url = input.value.trim();
  if (!url) { input.focus(); return; }

  state.currentURL = url;
  state.result = null;

  const scannerArea = document.getElementById('scannerArea');
  const progressCard = document.getElementById('progressCard');
  const resultArea = document.getElementById('resultArea');

  resultArea.innerHTML = '';
  progressCard.classList.remove('hidden');

  const progressFill = document.getElementById('progressFill');
  const progressPct = document.getElementById('progressPct');
  const stepEls = document.querySelectorAll('.step-pill');

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').textContent = '⟳ Scanning...';

  const steps = [10, 25, 40, 60, 75, 88, 95, 100];
  const stepThresholds = [25, 50, 75, 95];

  for (let i = 0; i < steps.length; i++) {
    await sleep(200 + Math.random() * 150);
    progressFill.style.width = steps[i] + '%';
    progressPct.textContent = steps[i] + '%';
    stepThresholds.forEach((threshold, idx) => {
      if (steps[i] >= threshold && stepEls[idx]) {
        stepEls[idx].classList.add('done');
        stepEls[idx].children[0].textContent = '✅';
      }
    });
  }

  const result = analyzeURL(url);
  state.result = result;

  // Add to history
  state.history.unshift({
    url,
    score: result.riskScore,
    verdict: result.verdict,
    timestamp: new Date(),
  });
  if (state.history.length > 20) state.history.pop();

  await sleep(300);
  progressCard.classList.add('hidden');
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanBtn').textContent = '⚡ Scan URL';

  // Reset step pills
  stepEls.forEach(el => { el.classList.remove('done'); el.children[0].textContent = '⏳'; });
  progressFill.style.width = '0%';

  resultArea.innerHTML = renderResult(result, url);

  // Bind result action buttons
  document.getElementById('copyReportBtn')?.addEventListener('click', () => {
    const text = `PhishGuard Report\nURL: ${url}\nRisk Score: ${result.riskScore}/100\nVerdict: ${result.verdict}\nFindings: ${result.findings.filter(f=>f.triggered).map(f=>f.label).join(', ')}`;
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById('copyReportBtn');
      if (btn) { btn.textContent = '✅ Copied!'; setTimeout(() => { btn.textContent = '📋 Copy Report'; }, 2000); }
    });
  });

  document.getElementById('newScanBtn')?.addEventListener('click', clearScan);

  document.getElementById('googleSBBtn')?.addEventListener('click', () => {
    window.open(`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(url)}`, '_blank', 'noopener,noreferrer');
  });

  resultArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function clearScan() {
  document.getElementById('urlInput').value = '';
  document.getElementById('resultArea').innerHTML = '';
  document.getElementById('progressCard').classList.add('hidden');
  state.result = null;
  state.currentURL = '';
  document.getElementById('urlInput').focus();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ════════════════════════════════════════════════════════════════════
// TAB MANAGEMENT
// ════════════════════════════════════════════════════════════════════

function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-content').forEach(el => {
    el.classList.toggle('active', el.id === tab + 'Tab');
  });
  if (tab === 'history') renderHistory();
}

// ════════════════════════════════════════════════════════════════════
// TYPING EFFECT
// ════════════════════════════════════════════════════════════════════

function startTypingEffect() {
  const placeholders = [
    'https://suspicious-bank-login.tk',
    'https://paypa1-secure.com/verify',
    'https://bit.ly/3xK9mP',
    'https://google.com',
    'https://amaz0n-deals.xyz/free-gift',
  ];
  const input = document.getElementById('urlInput');
  if (!input || input.value) return;

  let pi = 0, ci = 0, typing = true;
  let current = placeholders[0];

  setInterval(() => {
    if (input.value) return; // Stop if user types
    if (typing) {
      input.setAttribute('placeholder', current.slice(0, ++ci));
      if (ci >= current.length) { typing = false; }
    } else {
      ci--;
      input.setAttribute('placeholder', current.slice(0, ci));
      if (ci === 0) {
        pi = (pi + 1) % placeholders.length;
        current = placeholders[pi];
        typing = true;
      }
    }
  }, 80);
}

// ════════════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  // Tab buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Scan button
  document.getElementById('scanBtn')?.addEventListener('click', runScan);

  // Clear button
  document.getElementById('clearBtn')?.addEventListener('click', clearScan);

  // Enter key
  document.getElementById('urlInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') runScan();
  });

  // Quick test pills
  document.querySelectorAll('.quick-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.getElementById('urlInput').value = pill.dataset.url;
    });
  });

  // Start default tab
  switchTab('scanner');
  startTypingEffect();
});
