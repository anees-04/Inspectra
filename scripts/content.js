// Content script that runs on all pages
// This script will be injected and can access the DOM

console.log('Security Scanner content script loaded');

// Message listener for popup/background
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  try {
    if (!message || !message.action) return;

    function focusLineForDisplay(lineText, highlight, column) {
      const raw = String(lineText || '');
      if (!raw) return '';

      const maxLen = 220;
      if (raw.length <= maxLen) return raw;

      const needle = (highlight && String(highlight).trim().length > 0) ? String(highlight) : '';
      let center = -1;
      if (needle) {
        center = raw.indexOf(needle);
        if (center === -1) center = raw.toLowerCase().indexOf(needle.toLowerCase());
      }
      if (center === -1 && typeof column === 'number' && Number.isFinite(column) && column >= 1) {
        center = Math.max(0, Math.min(raw.length - 1, column - 1));
      }
      if (center === -1) center = 0;

      const radius = Math.floor(maxLen / 2);
      const start = Math.max(0, center - radius);
      const end = Math.min(raw.length, start + maxLen);
      const prefix = start > 0 ? '…' : '';
      const suffix = end < raw.length ? '…' : '';
      return `${prefix}${raw.slice(start, end)}${suffix}`;
    }

    if (message.action === 'ping') {
      sendResponse({ ok: true });
      return;
    }

    if (message.action === 'scan') {
      const scanId = message.scanId || String(Date.now());

      (async () => {
        const results = await performSecurityScanStepwise(scanId);
        sendResponse({ ok: true, results });
      })().catch((err) => {
        sendResponse({ ok: false, error: err && err.message ? err.message : String(err), results: [] });
      });

      return true;
    }

    if (message.action === 'getSourceContext') {
      const line = Number(message.line);
      const selector = message.selector ? String(message.selector) : null;
      const mode = message.mode ? String(message.mode) : 'line';
      const highlight = message.highlight ? String(message.highlight) : null;
      const radius = Number.isFinite(Number(message.radius)) ? Math.max(0, Math.min(20, Number(message.radius))) : 0;

      let resolvedLine = Number.isFinite(line) && line >= 1 ? line : null;
      let resolvedColumn = null;

      // If selector is provided, we can return a more actionable context: the element tag itself.
      if (selector && mode === 'element') {
        try {
          const el = document.querySelector(selector);
          if (el) {
            const outer = el.outerHTML || '';
            const openTagEnd = outer.indexOf('>');
            const openTag = openTagEnd >= 0 ? outer.slice(0, openTagEnd + 1) : outer;
            const locator = createBestEffortLocator();
            const lc = (highlight && String(highlight).trim().length > 0)
              ? (locator.findLineColForTextInElement(el, String(highlight)) || locator.findLineColForElement(el))
              : locator.findLineColForElement(el);

            const contextLineRaw = (lc && typeof lc.line === 'number') ? locator.getLineText(lc.line) : '';
            const contextLine = focusLineForDisplay(contextLineRaw, highlight, lc && typeof lc.column === 'number' ? lc.column : null);
            sendResponse({
              ok: true,
              mode: 'element',
              selector,
              tagName: String(el.tagName || '').toLowerCase(),
              openTag,
              contextLine: contextLine || null,
              outerHTML: outer,
              highlight,
              line: lc && typeof lc.line === 'number' ? lc.line : null,
              column: lc && typeof lc.column === 'number' ? lc.column : null
            });
            return;
          }
        } catch {
          // fall back to line-based context
        }
      }

      if (!resolvedLine && selector) {
        try {
          const el = document.querySelector(selector);
          const locator = createBestEffortLocator();
          const lc = locator.findLineColForElement(el);
          if (lc && typeof lc.line === 'number') {
            resolvedLine = lc.line;
            resolvedColumn = typeof lc.column === 'number' ? lc.column : null;
          }
        } catch {
          // ignore
        }
      }

      if (!resolvedLine) {
        sendResponse({ ok: false, error: 'No line information available for this issue.' });
        return;
      }

      const html = document.documentElement ? document.documentElement.outerHTML : '';
      const lines = html.split('\n');
      const idx = resolvedLine - 1;

      const start = Math.max(0, idx - radius);
      const end = Math.min(lines.length - 1, idx + radius);

      const snippet = [];
      for (let i = start; i <= end; i++) {
        const rawText = lines[i] ?? '';
        const cookedText = (i === idx)
          ? focusLineForDisplay(rawText, highlight, resolvedColumn)
          : (String(rawText).length > 220 ? `${String(rawText).slice(0, 219)}…` : String(rawText));
        snippet.push({
          line: i + 1,
          text: cookedText,
          isTarget: i === idx
        });
      }

      sendResponse({ ok: true, mode: 'line', snippet, totalLines: lines.length, line: resolvedLine, column: resolvedColumn, highlight });
      return;
    }
  } catch (err) {
    sendResponse({ ok: false, error: err && err.message ? err.message : String(err) });
  }
});

async function performSecurityScanStepwise(scanId) {
  console.log('Starting security scan...');

  const steps = [
    { label: 'Misconfiguration DB checks', fnName: 'runMisconfigurationDatabaseChecks' },
    { label: 'Session cookies (Set-Cookie)', fnName: 'checkSessionCookiesFromResponse' },
    { label: 'Content security', fnName: 'checkContentSecurity' },
    { label: 'Form security', fnName: 'checkFormSecurity' },
    { label: 'XSS signals', fnName: 'checkXSS' },
    { label: 'CSRF signals', fnName: 'checkCSRF' },
    { label: 'Input validation', fnName: 'checkInputValidation' },
    { label: 'Authentication', fnName: 'checkAuthentication' },
    { label: 'Session management', fnName: 'checkSessionManagement' },
    { label: 'Cryptography', fnName: 'checkCryptography' },
    { label: 'Access control', fnName: 'checkAccessControl' },
    { label: 'API endpoints', fnName: 'checkAPIEndpoints' },
    { label: 'Third-party scripts', fnName: 'checkThirdPartyScripts' },
    { label: 'Data exposure', fnName: 'checkDataExposure' },
    { label: 'Misc checks', fnName: 'checkMiscellaneous' }
  ];

  const issues = [];
  const total = steps.length;

  const locator = createBestEffortLocator();

  // Hard guard: if security-checks.js didn't load, fail fast with a clear error.
  const missing = steps
    .map(s => s.fnName)
    .filter(name => typeof globalThis[name] !== 'function');
  if (missing.length) {
    throw new Error(`Scanner functions missing: ${missing.join(', ')}. Ensure scripts/security-checks.js is loaded.`);
  }

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    sendProgress(scanId, i + 1, total, step.label);

    try {
      const maybeIssues = globalThis[step.fnName]();
      const stepIssues = await Promise.resolve(maybeIssues);
      if (Array.isArray(stepIssues) && stepIssues.length) {
        for (const issue of stepIssues) {
          if (issue && typeof issue === 'object' && !Array.isArray(issue)) {
            const enriched = {
              ...issue,
              checkFunction: issue.checkFunction || step.fnName
            };

            // If the check attached a DOM element reference, convert it to a selector + (best-effort) line/column.
            if (enriched.element && isElement(enriched.element)) {
              const selector = cssSelectorForElement(enriched.element);
              const needle = (enriched.highlight && String(enriched.highlight).trim())
                ? String(enriched.highlight)
                : null;

              const lineCol = needle
                ? (locator.findLineColForTextInElement(enriched.element, needle) || locator.findLineColForElement(enriched.element))
                : locator.findLineColForElement(enriched.element);

              enriched.location = {
                selector,
                ...(lineCol || {})
              };

              // Always include the exposed line content (best-effort) for code-based findings.
              // This is especially important for issues like eval()/inline scripts/API key exposure.
              if (lineCol && typeof lineCol.line === 'number') {
                const rawLine = locator.getLineText(lineCol.line);
                const shouldRedact = (() => {
                  const title = String(enriched.title || '').toLowerCase();
                  return title.includes('api key') || title.includes('access token') || title.includes('secret key') || title.includes('token exposed');
                })();

                const redactLongSecrets = (text) => {
                  // Mask long token-like sequences to avoid displaying full secrets.
                  // Keeps first/last 4 chars so the user can still correlate.
                  return String(text || '').replace(/[a-zA-Z0-9_-]{20,}/g, (m) => {
                    if (m.length <= 10) return m;
                    return `${m.slice(0, 4)}…${m.slice(-4)}`;
                  });
                };

                const raw = String(rawLine || '');

                // If the line is extremely long (common on minified apps), extract a focused window
                // around either the highlight token or the resolved column.
                const takeFocusedWindow = (text) => {
                  const s = String(text || '');
                  if (!s) return '';

                  const highlight = (enriched.highlight && String(enriched.highlight).trim().length > 0)
                    ? String(enriched.highlight)
                    : '';

                  let center = -1;
                  if (highlight) {
                    center = s.indexOf(highlight);
                    if (center === -1) center = s.toLowerCase().indexOf(highlight.toLowerCase());
                  }
                  if (center === -1 && lineCol && typeof lineCol.column === 'number') {
                    center = Math.max(0, Math.min(s.length - 1, Number(lineCol.column) - 1));
                  }
                  if (center === -1) center = 0;

                  const radius = 90;
                  const start = Math.max(0, center - radius);
                  const end = Math.min(s.length, center + radius);
                  const prefix = start > 0 ? '…' : '';
                  const suffix = end < s.length ? '…' : '';
                  return `${prefix}${s.slice(start, end)}${suffix}`;
                };

                const base = (shouldRedact || raw.length > 400) ? takeFocusedWindow(raw) : raw;
                const cooked = shouldRedact ? redactLongSecrets(base) : String(base || '');
                const lineText = String(cooked || '').trim().slice(0, 320);
                if (lineText) {
                  const lineEvidence = `Line ${lineCol.line}: ${lineText}`;
                  if (enriched.evidence && String(enriched.evidence).trim().length > 0) {
                    // Prepend line evidence so it's always visible even if the check already added evidence.
                    enriched.evidence = `${lineEvidence}\n${String(enriched.evidence)}`;
                  } else {
                    enriched.evidence = lineEvidence;
                  }
                }
              }
              delete enriched.element;
            }

            issues.push(enriched);
          } else {
            issues.push(issue);
          }
        }
      }
    } catch (error) {
      issues.push({
        title: `Scan step failed: ${step.label}`,
        description: `An error occurred while running ${step.fnName}: ${error.message}`,
        severity: 'high',
        recommendation: 'Try rescanning. If it persists, report this bug with the page URL.',
        checkFunction: step.fnName
      });
    }

    // Yield so the popup can receive progress updates smoothly.
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  sendProgress(scanId, total, total, 'Complete');

  function dedupeIssues(items) {
    if (!Array.isArray(items)) return [];
    const seen = new Set();
    const out = [];

    for (const it of items) {
      if (!it || typeof it !== 'object') {
        // primitive entries are unexpected, but keep them and dedupe by value
        const k = `prim|${String(it)}`;
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(it);
        continue;
      }

      const title = String(it.title || '').trim().toLowerCase();
      const check = String(it.checkFunction || '').trim();
      const highlight = String(it.highlight || '').trim().toLowerCase();
      const loc = (it.location && typeof it.location === 'object') ? it.location : {};
      const selector = String(loc.selector || '');
      const line = (typeof loc.line === 'number') ? loc.line : '';
      const column = (typeof loc.column === 'number') ? loc.column : '';
      const evidenceFirstLine = it.evidence ? String(it.evidence).split('\n')[0].trim().slice(0, 240) : '';

      // Stable-ish fingerprint: same check + same title + same location + same evidence line.
      const key = [check, title, selector, line, column, highlight, evidenceFirstLine].join('|');
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(it);
    }

    return out;
  }

  const dedupedIssues = dedupeIssues(issues);

  // Update badge via background
  try {
    const severity = getHighestSeverity(dedupedIssues);
    chrome.runtime.sendMessage({ action: 'updateBadge', count: dedupedIssues.length, severity });
  } catch (_) {
    // best-effort
  }

  console.log(`Scan complete. Found ${dedupedIssues.length} unique issues.`);

  // Enrich issues with database metadata (id/category/CWE/OWASP/recommendation)
  // if the misconfiguration DB was loaded (data/misconfigurations-*.js).
  try {
    return enrichIssuesFromDatabase(dedupedIssues);
  } catch (_) {
    return dedupedIssues;
  }
}

function enrichIssuesFromDatabase(issues) {
  if (!Array.isArray(issues)) return [];

  const db = globalThis.MISCONFIG_DB;
  if (!db || !Array.isArray(db.all)) return issues;

  const titleToItem = new Map();
  for (const item of db.all) {
    if (!item || !item.title) continue;
    const key = normalizeTitle(item.title);
    if (!titleToItem.has(key)) titleToItem.set(key, item);
  }

  return issues.map((issue) => {
    if (!issue || !issue.title) return issue;

    let match = null;
    if (issue.checkFunction && db.byCheckFunction && typeof db.byCheckFunction.get === 'function') {
      const candidates = db.byCheckFunction.get(String(issue.checkFunction));
      if (Array.isArray(candidates) && candidates.length) {
        const wanted = normalizeTitle(issue.title);
        match = candidates.find(c => c && c.title && normalizeTitle(c.title) === wanted) || candidates[0];
      }
    }

    if (!match) {
      match = titleToItem.get(normalizeTitle(issue.title)) || null;
    }
    if (!match) return issue;

    return {
      ...issue,
      misconfigId: match.id ?? issue.misconfigId,
      category: match.category ?? issue.category,
      cwe: match.cwe ?? issue.cwe,
      owasp: match.owasp ?? issue.owasp,
      severity: (issue.severity && String(issue.severity).trim()) ? issue.severity : (match.severity ?? issue.severity),
      recommendation: (issue.recommendation && String(issue.recommendation).trim())
        ? issue.recommendation
        : (match.recommendation ?? issue.recommendation)
    };
  });
}

function normalizeTitle(title) {
  return String(title).trim().toLowerCase().replace(/\s+/g, ' ');
}

function getResponseHeadersSnapshot() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'getResponseHeaders' }, (resp) => {
      if (chrome.runtime.lastError) {
        resolve(null);
        return;
      }
      if (!resp || resp.ok !== true) {
        resolve(null);
        return;
      }
      resolve(resp.snapshot || null);
    });
  });
}

let __responseHeadersSnapshotPromise = null;
function getResponseHeadersSnapshotCached() {
  if (__responseHeadersSnapshotPromise) return __responseHeadersSnapshotPromise;
  __responseHeadersSnapshotPromise = getResponseHeadersSnapshot();
  return __responseHeadersSnapshotPromise;
}

function firstHeaderValue(headers, nameLower) {
  const values = headers && headers[nameLower];
  if (!values || !values.length) return null;
  return String(values[0]);
}

function allHeaderValues(headers, nameLower) {
  const values = headers && headers[nameLower];
  if (!values || !values.length) return [];
  return values.map(v => String(v));
}

function trunc(text, maxLen) {
  const s = String(text || '');
  if (s.length <= maxLen) return s;
  return `${s.slice(0, Math.max(0, maxLen - 1))}…`;
}

function headerLine(name, value) {
  const n = String(name || '').trim();
  if (!value) return `Header ${n}: (missing)`;
  return `Header ${n}: ${trunc(value, 320)}`;
}

function parseHstsDirectives(hstsValue) {
  const s = String(hstsValue || '');
  const parts = s.split(';').map(p => p.trim()).filter(Boolean);
  const directives = new Set(parts.map(p => p.toLowerCase()));
  const maxAgeMatch = s.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
  return { directives, maxAge };
}

function getHeaderJoined(headers, nameLower) {
  const values = allHeaderValues(headers, nameLower);
  if (!values.length) return '';
  return values.join(' ');
}

function parseCspDirectives(cspValue) {
  const raw = String(cspValue || '');
  const map = new Map();
  if (!raw) return { raw, map };

  // Very lightweight parser: split directives by ';' then tokenize by whitespace.
  const parts = raw.split(';').map(p => p.trim()).filter(Boolean);
  for (const p of parts) {
    const tokens = p.split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    const sources = tokens.slice(1);
    map.set(name, sources);
  }
  return { raw, map };
}

function cspSourcesFor(dirs, name) {
  if (!dirs || !dirs.map) return [];
  const n = String(name || '').toLowerCase();
  const exact = dirs.map.get(n);
  if (Array.isArray(exact)) return exact;
  return [];
}

function cspEffectiveSources(dirs, directiveName) {
  const dn = String(directiveName || '').toLowerCase();
  const own = cspSourcesFor(dirs, dn);
  if (own.length) return own;
  return cspSourcesFor(dirs, 'default-src');
}

function cspHasToken(dirs, directiveName, token) {
  const t = String(token || '').toLowerCase();
  const sources = cspEffectiveSources(dirs, directiveName);
  return sources.some(s => String(s).toLowerCase() === t);
}

function pageLooksSensitive() {
  try {
    const password = document.querySelector('input[type="password"], input[autocomplete="current-password"], input[autocomplete="new-password"]');
    if (password) return { sensitive: true, el: password };
    const cc = document.querySelector('input[autocomplete^="cc-"], input[name*="card" i], input[id*="card" i]');
    if (cc) return { sensitive: true, el: cc };
    return { sensitive: false, el: null };
  } catch {
    return { sensitive: false, el: null };
  }
}

// -------------------- CSP checks (passive, strict) --------------------
async function checkCSP() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  const cspRO = headers ? getHeaderJoined(headers, 'content-security-policy-report-only') : '';
  if (!csp && !cspRO) {
    out.push({
      title: 'Missing Content-Security-Policy Header',
      description: 'No CSP protection against XSS and injection attacks',
      recommendation: 'Implement a strict Content-Security-Policy',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSP'
    });
  }
  return out;
}

async function checkCSPUnsafeInline() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (cspHasToken(parsed, 'script-src', "'unsafe-inline'")) {
    out.push({
      title: "CSP Using 'unsafe-inline' for Scripts",
      description: 'CSP allows inline scripts, weakening XSS protection',
      recommendation: "Remove 'unsafe-inline' and use nonces/hashes",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPUnsafeInline'
    });
  }
  return out;
}

async function checkCSPUnsafeEval() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (cspHasToken(parsed, 'script-src', "'unsafe-eval'")) {
    out.push({
      title: "CSP Using 'unsafe-eval'",
      description: 'CSP allows eval() and similar functions',
      recommendation: "Remove 'unsafe-eval' from CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPUnsafeEval'
    });
  }
  return out;
}

async function checkCSPWildcard() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  const def = cspSourcesFor(parsed, 'default-src');
  if (def.some(s => String(s).trim() === '*')) {
    out.push({
      title: "CSP default-src Set to '*'",
      description: 'CSP allows any origin by default',
      recommendation: "Restrict default-src to 'self' and required origins",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPWildcard'
    });
  }
  return out;
}

async function checkCSPDataURI() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  const sources = cspEffectiveSources(parsed, 'script-src').map(s => String(s).toLowerCase());
  if (sources.includes('data:')) {
    out.push({
      title: 'CSP script-src Using Data: URI',
      description: 'CSP allows data: sources for scripts',
      recommendation: 'Remove data: from script-src',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPDataURI'
    });
  }
  return out;
}

async function checkCSPBaseUri() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (!parsed.map.has('base-uri')) {
    out.push({
      title: 'CSP Missing base-uri Directive',
      description: 'base-uri is not restricted, allowing base tag injection risks',
      recommendation: "Add 'base-uri 'self'' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPBaseUri'
    });
  }
  return out;
}

async function checkCSPFormAction() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (!parsed.map.has('form-action')) {
    out.push({
      title: 'CSP Missing form-action Directive',
      description: 'form-action is not restricted, increasing exfiltration risk via form submissions',
      recommendation: "Add 'form-action 'self'' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPFormAction'
    });
  }
  return out;
}

async function checkCSPFrameAncestors() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (!parsed.map.has('frame-ancestors')) {
    out.push({
      title: 'CSP Missing frame-ancestors',
      description: 'Clickjacking protection not configured in CSP',
      recommendation: "Add 'frame-ancestors 'none'' or 'self'",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPFrameAncestors'
    });
  }
  return out;
}

async function checkCSPUnsafeHashes() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (cspHasToken(parsed, 'script-src', "'unsafe-hashes'") || cspHasToken(parsed, 'style-src', "'unsafe-hashes'")) {
    out.push({
      title: "CSP Using 'unsafe-hashes'",
      description: 'CSP allows unsafe-hashes, which can weaken inline handler protections',
      recommendation: 'Avoid unsafe-hashes unless you fully understand the trade-offs',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPUnsafeHashes'
    });
  }
  return out;
}

async function checkCSPReportOnly() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  const cspRO = headers ? getHeaderJoined(headers, 'content-security-policy-report-only') : '';
  if (!csp && cspRO) {
    out.push({
      title: 'CSP Report-Only Mode in Production',
      description: "CSP in report-only mode doesn't block violations",
      recommendation: 'Switch from Content-Security-Policy-Report-Only to enforcing mode',
      evidence: headerLine('Content-Security-Policy-Report-Only', cspRO),
      checkFunction: 'checkCSPReportOnly'
    });
  }
  return out;
}

async function checkCSPObjectSrc() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (!parsed.map.has('object-src')) {
    out.push({
      title: 'CSP Missing object-src Restriction',
      description: 'object-src is not restricted; plugins/embeds may be allowed by default-src fallback',
      recommendation: "Add 'object-src 'none'' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPObjectSrc'
    });
  }
  return out;
}

async function checkCSPWasm() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  if (/wasm-unsafe-eval/i.test(csp)) {
    out.push({
      title: 'CSP Allows Unsafe WebAssembly',
      description: 'CSP allows wasm-unsafe-eval',
      recommendation: 'Avoid wasm-unsafe-eval unless absolutely necessary',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPWasm'
    });
  }
  return out;
}

async function checkCSPUpgrade() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  if (!/upgrade-insecure-requests/i.test(csp)) {
    out.push({
      title: 'CSP Missing upgrade-insecure-requests',
      description: 'CSP does not upgrade insecure requests',
      recommendation: "Add 'upgrade-insecure-requests' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPUpgrade'
    });
  }
  return out;
}

async function checkCSPMixedContent() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  if (!/block-all-mixed-content/i.test(csp)) {
    out.push({
      title: 'CSP Missing block-all-mixed-content',
      description: 'CSP does not block mixed content by policy',
      recommendation: "Add 'block-all-mixed-content' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPMixedContent'
    });
  }
  return out;
}

async function checkCSPHTTP() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  if (/\bhttp:\/\//i.test(csp) || /\bhttp:/i.test(csp)) {
    out.push({
      title: 'CSP Using HTTP URLs',
      description: 'CSP sources include HTTP URLs',
      recommendation: 'Use only HTTPS URLs in CSP directives',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPHTTP'
    });
  }
  return out;
}

async function checkCSPReporting() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  const cspRO = headers ? getHeaderJoined(headers, 'content-security-policy-report-only') : '';
  const effective = csp || cspRO;
  if (!effective) return out;

  if (!/\breport-uri\b/i.test(effective) && !/\breport-to\b/i.test(effective)) {
    out.push({
      title: 'CSP Missing report-uri or report-to',
      description: 'CSP violations not being reported',
      recommendation: 'Configure report-uri/report-to to monitor CSP violations',
      evidence: headerLine(csp ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only', effective),
      checkFunction: 'checkCSPReporting'
    });
  }
  return out;
}

async function checkCSPPermissive() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;

  const parsed = parseCspDirectives(csp);
  const tokens = [
    ...cspEffectiveSources(parsed, 'default-src'),
    ...cspEffectiveSources(parsed, 'script-src'),
    ...cspEffectiveSources(parsed, 'style-src')
  ].map(s => String(s).toLowerCase());

  // Keep this strict to avoid noisy false positives: flag only truly broad sources.
  const permissive = tokens.includes('*') || tokens.includes('http:') || tokens.includes('https:') || tokens.includes('data:');
  if (permissive) {
    out.push({
      title: 'CSP Too Permissive',
      description: 'CSP has overly broad permissions',
      recommendation: 'Implement principle of least privilege in CSP',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPPermissive'
    });
  }
  return out;
}

async function checkCSPChildSrc() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  if (parsed.map.has('child-src')) {
    out.push({
      title: 'CSP Using Deprecated child-src',
      description: 'Using deprecated child-src instead of frame-src and worker-src',
      recommendation: 'Replace child-src with frame-src and worker-src',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPChildSrc'
    });
  }
  return out;
}

async function checkCSPManifestSrc() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;

  // Avoid noisy warnings: only relevant if the page declares a web app manifest.
  const manifestEl = document.querySelector('link[rel="manifest"]');
  if (!manifestEl) return out;

  const parsed = parseCspDirectives(csp);
  const effective = cspEffectiveSources(parsed, 'manifest-src').map(s => String(s).toLowerCase());
  const hasDirective = parsed.map.has('manifest-src');

  const permissive = effective.length === 0 || effective.includes('*') || effective.includes('http:') || effective.includes('https:') || effective.includes('data:') || effective.includes('blob:');
  const strictSelfOnly = effective.length > 0 && effective.every(t => t === "'self'" || t === "'none'");

  if (!hasDirective && permissive && !strictSelfOnly) {
    out.push({
      title: 'CSP manifest-src Not Restricted',
      description: 'Web app manifest source not restricted',
      recommendation: "Add 'manifest-src 'self'' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPManifestSrc',
      highlight: 'manifest',
      element: manifestEl
    });
  }

  return out;
}

async function checkCSPWorkerSrc() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);

  const effective = cspEffectiveSources(parsed, 'worker-src').map(s => String(s).toLowerCase());
  const hasDirective = parsed.map.has('worker-src');
  const permissiveToken = new Set(['*', 'http:', 'https:', 'data:', 'blob:', 'filesystem:', 'file:']);
  const permissive = effective.length === 0 || effective.some(t => permissiveToken.has(t));

  if (!hasDirective && permissive) {
    out.push({
      title: 'CSP worker-src Not Restricted',
      description: 'Web worker sources not restricted',
      recommendation: "Add 'worker-src 'self'' to CSP",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPWorkerSrc'
    });
  }

  return out;
}

async function checkCSPStyleUnsafeInline() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  const hasUnsafeInline =
    cspHasToken(parsed, 'style-src', "'unsafe-inline'") ||
    cspHasToken(parsed, 'style-src-elem', "'unsafe-inline'") ||
    cspHasToken(parsed, 'style-src-attr', "'unsafe-inline'");

  if (hasUnsafeInline) {
    out.push({
      title: "CSP style-src Allows 'unsafe-inline'",
      description: 'Inline styles allowed, increasing XSS risk',
      recommendation: 'Use nonces or hashes for inline styles',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPStyleUnsafeInline'
    });
  }
  return out;
}

async function checkCSPImgDataUri() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  const parsed = parseCspDirectives(csp);
  const sources = cspEffectiveSources(parsed, 'img-src').map(s => String(s).toLowerCase());
  if (sources.includes('data:')) {
    out.push({
      title: 'CSP img-src Allows Data URIs',
      description: 'Data URIs in images can be exploited',
      recommendation: 'Evaluate if data: URIs are necessary for img-src',
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPImgDataUri'
    });
  }
  return out;
}

async function checkCSPTrustedTypes() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  if (!('trustedTypes' in window)) return out;

  const parsed = parseCspDirectives(csp);
  if (!parsed.map.has('trusted-types')) {
    out.push({
      title: 'CSP Missing trusted-types',
      description: 'Trusted Types not enforced for DOM manipulation',
      recommendation: "Add 'trusted-types' directive to prevent DOM XSS",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPTrustedTypes'
    });
  }
  return out;
}

async function checkCSPRequireTrustedTypes() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const csp = headers ? getHeaderJoined(headers, 'content-security-policy') : '';
  if (!csp) return out;
  if (!('trustedTypes' in window)) return out;

  const parsed = parseCspDirectives(csp);
  const tokens = cspSourcesFor(parsed, 'require-trusted-types-for').map(s => String(s).toLowerCase());
  const hasScript = tokens.some(t => t === "'script'");
  if (!hasScript) {
    out.push({
      title: 'CSP require-trusted-types-for Not Set',
      description: 'Trusted Types enforcement not enabled',
      recommendation: "Add 'require-trusted-types-for 'script'' directive",
      evidence: headerLine('Content-Security-Policy', csp),
      checkFunction: 'checkCSPRequireTrustedTypes'
    });
  }
  return out;
}

// -------------------- Cache-control checks (passive) --------------------
async function checkCacheControlSensitive() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const cacheControl = headers ? firstHeaderValue(headers, 'cache-control') : null;
  const pragma = headers ? firstHeaderValue(headers, 'pragma') : null;

  const { sensitive, el } = pageLooksSensitive();
  if (!sensitive) return out;

  const cc = String(cacheControl || '').toLowerCase();
  const hasGood = cc.includes('no-store') || (cc.includes('no-cache') && cc.includes('private')) || cc.includes('must-revalidate');
  if (!cacheControl || !hasGood) {
    out.push({
      title: 'Missing Cache-Control for Sensitive Pages',
      description: 'Sensitive pages lack proper cache control',
      recommendation: "Set 'Cache-Control: no-store, no-cache, must-revalidate, private' for sensitive pages",
      evidence: headerLine('Cache-Control', cacheControl),
      checkFunction: 'checkCacheControlSensitive',
      highlight: 'password',
      element: el || undefined
    });
  }

  // Backwards-compat: only warn about Pragma when the page is sensitive.
  if (!pragma) {
    out.push({
      title: 'Missing Pragma: no-cache',
      description: 'Pragma: no-cache not set for backwards compatibility with older caches',
      recommendation: "Add 'Pragma: no-cache' for backwards compatibility",
      evidence: headerLine('Pragma', pragma),
      checkFunction: 'checkPragma',
      highlight: 'password',
      element: el || undefined
    });
  }

  return out;
}

// Keep the DB function name too (some items reference checkPragma directly).
async function checkPragma() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const pragma = headers ? firstHeaderValue(headers, 'pragma') : null;
  const { sensitive, el } = pageLooksSensitive();
  if (!sensitive) return out;
  if (!pragma) {
    out.push({
      title: 'Missing Pragma: no-cache',
      description: 'Pragma: no-cache not set for backwards compatibility with older caches',
      recommendation: "Add 'Pragma: no-cache' for backwards compatibility",
      evidence: headerLine('Pragma', pragma),
      checkFunction: 'checkPragma',
      highlight: 'password',
      element: el || undefined
    });
  }
  return out;
}

// -------------------- CORS checks (passive, main document only) --------------------
async function checkCORSWildcardCredentials() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  const acc = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-credentials'));
  if (acao === '*' && acc.toLowerCase() === 'true') {
    out.push({
      title: 'CORS Wildcard with Credentials',
      description: 'Access-Control-Allow-Origin: * with credentials',
      recommendation: 'Never use wildcard origin with credentials. Reflect only trusted origins and add Vary: Origin.',
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Access-Control-Allow-Credentials', acc)}`,
      checkFunction: 'checkCORSWildcardCredentials'
    });
  }
  return out;
}

async function checkCORSWildcard() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  if (acao === '*') {
    out.push({
      title: 'CORS Allows Any Origin',
      description: 'Access-Control-Allow-Origin set to *',
      recommendation: 'Restrict Access-Control-Allow-Origin to a specific allowlist.',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSWildcard'
    });
  }
  return out;
}

async function checkCORSNullOrigin() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  if (acao.toLowerCase() === 'null') {
    out.push({
      title: 'CORS Allows Null Origin',
      description: 'Null origin accepted in CORS policy',
      recommendation: 'Avoid allowing null origin; restrict to trusted https origins.',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSNullOrigin'
    });
  }
  return out;
}

async function checkCORSFileProtocol() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  if (acao.toLowerCase().includes('file://')) {
    out.push({
      title: 'CORS Allows File:// Protocol',
      description: 'File protocol accepted in CORS origin',
      recommendation: 'Do not allow file:// origins in production CORS policies.',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSFileProtocol'
    });
  }
  return out;
}

async function checkCORSLocalhost() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  if (/localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(acao)) {
    out.push({
      title: 'CORS Allows Localhost Origins',
      description: 'Localhost allowed in production CORS policy',
      recommendation: 'Remove localhost from production CORS whitelist',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSLocalhost'
    });
  }
  return out;
}

async function checkCORSDevOrigins() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  // Avoid duplicating `checkCORSLocalhost`: focus on other common dev/staging origins.
  if (!/localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(acao) && /(\bdev\b|\bstaging\b|\.local\b|\.test\b|\.internal\b|\.example\b|ngrok\b)/i.test(acao)) {
    out.push({
      title: 'CORS Development Origins in Production',
      description: 'Development origins appear in CORS allowlist',
      recommendation: 'Remove development origins (localhost) from production allowlists',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSDevOrigins'
    });
  }
  return out;
}

async function checkCORSSubdomainWildcard() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  // ACAO must be either '*' or an exact origin. Any other '*' usage is invalid/unsafe.
  if (acao && acao !== '*' && acao.includes('*')) {
    out.push({
      title: 'CORS Subdomain Wildcard',
      description: 'Overly permissive subdomain wildcard in CORS',
      recommendation: 'Explicitly list trusted subdomains',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSSubdomainWildcard'
    });
  }
  return out;
}

async function checkCORSVaryHeader() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  if (!acao) return out;
  if (acao === '*') return out;

  // If a specific origin is returned, caches must vary on Origin to avoid poisoning/cross-user mixups.
  const vary = getHeaderJoined(headers, 'vary');
  const varyLower = String(vary || '').toLowerCase();
  const looksLikeOrigin = /^https?:\/\//i.test(acao) || acao.toLowerCase() === 'null';
  if (looksLikeOrigin && !varyLower.split(',').map(s => s.trim()).includes('origin')) {
    out.push({
      title: 'CORS Missing Vary Header',
      description: 'Vary: Origin header not set with CORS',
      recommendation: "Add 'Vary: Origin' header for cache correctness",
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Vary', vary)}`,
      checkFunction: 'checkCORSVaryHeader'
    });
  }
  return out;
}

async function checkCORSAllowHeaders() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;

  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  const allowHeaders = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-headers'));
  if (!acao || !allowHeaders) return out;

  const tokens = allowHeaders.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const hasWildcard = tokens.includes('*');
  // Very conservative: flag only wildcard, or allowing credentials-ish headers alongside wildcard origins.
  const sensitive = new Set(['authorization', 'x-api-key', 'x-amz-security-token', 'x-auth-token']);
  const hasSensitive = tokens.some(t => sensitive.has(t));

  if (hasWildcard || (acao === '*' && hasSensitive)) {
    out.push({
      title: 'CORS Allow-Headers Too Permissive',
      description: 'Access-Control-Allow-Headers is overly permissive',
      recommendation: 'Restrict Access-Control-Allow-Headers to the minimum required headers.',
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Access-Control-Allow-Headers', allowHeaders)}`,
      checkFunction: 'checkCORSAllowHeaders',
      severity: 'medium'
    });
  }

  return out;
}

async function checkCORSExposeHeaders() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;

  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  const expose = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-expose-headers'));
  if (!acao || !expose) return out;

  const tokens = expose.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  // set-cookie is not supposed to be exposed; also avoid exposing auth-ish headers.
  const risky = new Set(['set-cookie', 'authorization', 'x-api-key', 'x-amz-security-token', 'x-auth-token']);
  const hit = tokens.find(t => risky.has(t));
  if (hit) {
    out.push({
      title: 'CORS Exposes Sensitive Headers',
      description: 'Access-Control-Expose-Headers includes sensitive headers',
      recommendation: 'Remove sensitive headers from Access-Control-Expose-Headers unless strictly necessary.',
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Access-Control-Expose-Headers', expose)}`,
      checkFunction: 'checkCORSExposeHeaders',
      severity: 'medium'
    });
  }

  return out;
}

async function checkCORSMethods() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;

  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  const allowMethods = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-methods'));
  if (!acao || !allowMethods) return out;

  const methods = allowMethods.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  if (!methods.length) return out;

  if (methods.includes('TRACE')) {
    out.push({
      title: 'CORS Allows TRACE Method',
      description: 'TRACE is enabled via CORS allow-methods',
      recommendation: 'Disable TRACE and restrict allowed methods.',
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Access-Control-Allow-Methods', allowMethods)}`,
      checkFunction: 'checkCORSMethods',
      severity: 'high'
    });
    return out;
  }

  const risky = ['PUT', 'DELETE', 'PATCH'];
  const hasRisky = risky.some(m => methods.includes(m));
  if (hasRisky && acao === '*') {
    out.push({
      title: 'CORS Allows Dangerous Methods Broadly',
      description: 'CORS allows state-changing methods with wildcard origin',
      recommendation: 'Restrict allowed origins and limit allowed methods to what is required.',
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Access-Control-Allow-Methods', allowMethods)}`,
      checkFunction: 'checkCORSMethods',
      severity: 'medium'
    });
  }

  return out;
}

async function checkCORSMaxAge() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;

  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  const maxAgeRaw = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-max-age'));
  if (!acao || !maxAgeRaw) return out;

  const maxAge = Number(String(maxAgeRaw).match(/\d+/)?.[0] || NaN);
  if (!Number.isFinite(maxAge)) return out;

  // Conservative: only warn when very large (>= 1 day), which can prolong incorrect policy caching.
  if (maxAge >= 86400) {
    out.push({
      title: 'CORS Preflight Cache Max-Age Too High',
      description: 'Access-Control-Max-Age is very high; policy changes may take long to propagate',
      recommendation: 'Use a smaller Access-Control-Max-Age unless you have a strong operational reason.',
      evidence: `${headerLine('Access-Control-Allow-Origin', acao)}\n${headerLine('Access-Control-Max-Age', maxAgeRaw)}`,
      checkFunction: 'checkCORSMaxAge',
      severity: 'low'
    });
  }

  return out;
}

async function checkCORSMixedProtocol() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const acao = normalizeHeaderValue(firstHeaderValue(headers, 'access-control-allow-origin'));
  if (!acao) return out;

  // If a specific HTTP origin is allowed, this is usually unsafe on HTTPS sites.
  const isHttps = window.location && window.location.protocol === 'https:';
  if (isHttps && /^http:\/\//i.test(acao)) {
    out.push({
      title: 'CORS Allows HTTP Origin on HTTPS Site',
      description: 'CORS allow-origin includes an http:// origin while the site is served over https://',
      recommendation: 'Allow only https:// origins in production CORS policies.',
      evidence: headerLine('Access-Control-Allow-Origin', acao),
      checkFunction: 'checkCORSMixedProtocol',
      severity: 'medium'
    });
  }
  return out;
}

function normalizeHeaderValue(value) {
  return String(value || '').trim();
}

async function getHeadersOrNull() {
  const snapshot = await getResponseHeadersSnapshotCached();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  return { snapshot, headers };
}

// -------------------- Misconfiguration DB runner --------------------
async function runMisconfigurationDatabaseChecks() {
  const issues = [];

  // If the DB isn't loaded, fall back gracefully.
  const db = globalThis.MISCONFIG_DB;
  if (!db || !db.byCheckFunction || typeof db.byCheckFunction.keys !== 'function') {
    return issues;
  }

  const coverage = {
    total: 0,
    implemented: 0,
    executed: 0,
    produced: 0,
    missing: 0,
    errors: 0,
    missingNames: [],
    errorNames: []
  };

  // First: header snapshot availability notice (best-effort).
  const { snapshot, headers } = await getHeadersOrNull();
  if (!headers) {
    issues.push({
      title: 'Response headers not available',
      description: 'Could not read HTTP response headers for this page. Header-based misconfiguration checks may be incomplete.',
      recommendation: 'Reload the page and rescan. Note: some restricted pages cannot be inspected.',
      severity: 'low',
      checkFunction: 'runMisconfigurationDatabaseChecks',
      evidence: snapshot && snapshot.url ? `URL: ${String(snapshot.url)}` : undefined
    });
    // Continue: DOM-based checks may still work.
  }

  const seenFn = new Set();
  for (const fnName of db.byCheckFunction.keys()) {
    const name = String(fnName || '').trim();
    if (!name || seenFn.has(name)) continue;
    seenFn.add(name);

    coverage.total += 1;
    const fn = globalThis[name];
    if (typeof fn !== 'function') {
      coverage.missing += 1;
      if (coverage.missingNames.length < 25) coverage.missingNames.push(name);
      continue;
    }

    coverage.implemented += 1;

    try {
      coverage.executed += 1;
      const out = await Promise.resolve(fn());
      if (!Array.isArray(out) || out.length === 0) continue;
      coverage.produced += out.length;
      for (const issue of out) {
        if (!issue || typeof issue !== 'object' || Array.isArray(issue)) continue;
        issues.push({
          ...issue,
          checkFunction: issue.checkFunction || name
        });
      }
    } catch (_) {
      // Best-effort: ignore individual check failures.
      coverage.errors += 1;
      if (coverage.errorNames.length < 25) coverage.errorNames.push(name);
    }
  }

  // Single informational item to show how much of the DB is actually being used.
  issues.push({
    title: 'Misconfiguration DB Coverage Summary',
    description: 'Shows which DB checkFunctions are implemented and executed (passive mode).',
    recommendation: 'Implement missing checkFunctions where passive evidence is possible (headers/DOM only).',
    severity: 'low',
    checkFunction: 'misconfigCoverage',
    evidence: [
      `Total DB checkFunctions: ${coverage.total}`,
      `Implemented (function exists): ${coverage.implemented}`,
      `Executed: ${coverage.executed}`,
      `Issues produced: ${coverage.produced}`,
      `Missing: ${coverage.missing}`,
      `Errors: ${coverage.errors}`,
      coverage.missingNames.length ? `Missing examples: ${coverage.missingNames.join(', ')}` : null,
      coverage.errorNames.length ? `Error examples: ${coverage.errorNames.join(', ')}` : null
    ].filter(Boolean).join('\n')
  });

  return issues;
}

// -------------------- TLS/SSL (passive) --------------------
async function checkHTTPS() {
  const out = [];
  try {
    const loc = window.location;
    if (!loc) return out;
    const host = String(loc.hostname || '').toLowerCase();
    const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1';
    if (loc.protocol === 'http:' && !isLocal) {
      out.push({
        title: 'Site Not Using HTTPS',
        description: 'Website served over unencrypted HTTP',
        recommendation: 'Implement HTTPS for all pages',
        evidence: `URL: ${String(loc.href || '')}`,
        checkFunction: 'checkHTTPS'
      });
    }
  } catch {
    // ignore
  }
  return out;
}

// -------------------- Header misconfiguration checks (low FP) --------------------
async function checkHSTSHeader() {
  const out = [];
  const isHttps = window.location && window.location.protocol === 'https:';
  const { headers } = await getHeadersOrNull();
  const hsts = headers ? firstHeaderValue(headers, 'strict-transport-security') : null;

  if (isHttps && !hsts) {
    out.push({
      title: 'Missing Strict-Transport-Security Header',
      description: 'HSTS header not configured, allowing SSL stripping attacks',
      recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
      evidence: headerLine('Strict-Transport-Security', hsts),
      checkFunction: 'checkHSTSHeader'
    });
  }
  return out;
}

async function checkHSTSMaxAge() {
  const out = [];
  const isHttps = window.location && window.location.protocol === 'https:';
  const { headers } = await getHeadersOrNull();
  const hsts = headers ? firstHeaderValue(headers, 'strict-transport-security') : null;
  if (!isHttps || !hsts) return out;

  const { maxAge } = parseHstsDirectives(hsts);
  if (typeof maxAge === 'number' && Number.isFinite(maxAge) && maxAge > 0 && maxAge < 31536000) {
    out.push({
      title: 'HSTS Max-Age Too Short',
      description: 'HSTS max-age is less than 1 year (31536000 seconds)',
      recommendation: 'Set HSTS max-age to at least 31536000 seconds (1 year)',
      evidence: headerLine('Strict-Transport-Security', hsts),
      checkFunction: 'checkHSTSMaxAge'
    });
  }
  return out;
}

async function checkHSTSSubdomains() {
  const out = [];
  const isHttps = window.location && window.location.protocol === 'https:';
  const { headers } = await getHeadersOrNull();
  const hsts = headers ? firstHeaderValue(headers, 'strict-transport-security') : null;
  if (!isHttps || !hsts) return out;

  const { directives } = parseHstsDirectives(hsts);
  if (directives && !directives.has('includesubdomains')) {
    out.push({
      title: 'HSTS Missing includeSubDomains',
      description: "HSTS header doesn't include subdomains directive",
      recommendation: "Add 'includeSubDomains' directive to HSTS header",
      evidence: headerLine('Strict-Transport-Security', hsts),
      checkFunction: 'checkHSTSSubdomains'
    });
  }
  return out;
}

async function checkXFrameOptions() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xfo = headers ? firstHeaderValue(headers, 'x-frame-options') : null;
  if (!xfo) {
    out.push({
      title: 'Missing X-Frame-Options Header',
      description: 'No clickjacking protection via X-Frame-Options',
      recommendation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
      evidence: headerLine('X-Frame-Options', xfo),
      checkFunction: 'checkXFrameOptions'
    });
  }
  return out;
}

async function checkXFrameAllowFrom() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xfo = headers ? firstHeaderValue(headers, 'x-frame-options') : null;
  if (!xfo) return out;
  const v = normalizeHeaderValue(xfo).toLowerCase();
  if (v.startsWith('allow-from')) {
    out.push({
      title: 'X-Frame-Options Set to ALLOW-FROM',
      description: 'Using deprecated ALLOW-FROM directive',
      recommendation: 'Use CSP frame-ancestors instead of X-Frame-Options ALLOW-FROM',
      evidence: headerLine('X-Frame-Options', xfo),
      checkFunction: 'checkXFrameAllowFrom'
    });
  }
  return out;
}

async function checkContentTypeOptions() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xcto = headers ? firstHeaderValue(headers, 'x-content-type-options') : null;
  if (!xcto) {
    out.push({
      title: 'Missing X-Content-Type-Options',
      description: 'Browser may MIME-sniff responses',
      recommendation: "Add 'X-Content-Type-Options: nosniff'",
      evidence: headerLine('X-Content-Type-Options', xcto),
      checkFunction: 'checkContentTypeOptions'
    });
  }
  return out;
}

async function checkReferrerPolicy() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const rp = headers ? firstHeaderValue(headers, 'referrer-policy') : null;
  if (!rp) {
    out.push({
      title: 'Missing Referrer-Policy Header',
      description: 'Referrer information may leak sensitive data',
      recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter",
      evidence: headerLine('Referrer-Policy', rp),
      checkFunction: 'checkReferrerPolicy'
    });
  }
  return out;
}

async function checkWeakReferrerPolicy() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const rp = headers ? firstHeaderValue(headers, 'referrer-policy') : null;
  if (!rp) return out;
  const v = normalizeHeaderValue(rp).toLowerCase();
  if (v === 'unsafe-url' || v === 'no-referrer-when-downgrade') {
    out.push({
      title: 'Weak Referrer-Policy',
      description: "Referrer-Policy set to 'unsafe-url' or 'no-referrer-when-downgrade'",
      recommendation: "Use 'strict-origin-when-cross-origin', 'no-referrer', or 'same-origin'",
      evidence: headerLine('Referrer-Policy', rp),
      checkFunction: 'checkWeakReferrerPolicy'
    });
  }
  return out;
}

async function checkPermissionsPolicy() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const pp = headers ? firstHeaderValue(headers, 'permissions-policy') : null;
  if (!pp) {
    out.push({
      title: 'Missing Permissions-Policy Header',
      description: 'Browser features not restricted via Permissions-Policy',
      recommendation: 'Add Permissions-Policy to control camera, microphone, geolocation, etc.',
      evidence: headerLine('Permissions-Policy', pp),
      checkFunction: 'checkPermissionsPolicy'
    });
  }
  return out;
}

async function checkXSSProtection() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xxp = headers ? firstHeaderValue(headers, 'x-xss-protection') : null;
  if (!xxp) {
    out.push({
      title: 'Missing X-XSS-Protection Header',
      description: 'Legacy XSS filter not enabled',
      recommendation: "Add 'X-XSS-Protection: 1; mode=block' (legacy; modern browsers may ignore it)",
      evidence: headerLine('X-XSS-Protection', xxp),
      checkFunction: 'checkXSSProtection',
      severity: 'low'
    });
  }
  return out;
}

async function checkXSSProtectionDisabled() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xxp = headers ? firstHeaderValue(headers, 'x-xss-protection') : null;
  if (!xxp) return out;
  const v = normalizeHeaderValue(xxp).toLowerCase();
  if (v === '0' || v.startsWith('0;')) {
    out.push({
      title: 'X-XSS-Protection Disabled',
      description: 'XSS protection explicitly disabled with value 0',
      recommendation: "Set 'X-XSS-Protection: 1; mode=block' (legacy; modern browsers may ignore it)",
      evidence: headerLine('X-XSS-Protection', xxp),
      checkFunction: 'checkXSSProtectionDisabled',
      severity: 'medium'
    });
  }
  return out;
}

async function checkDownloadOptions() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xdo = headers ? firstHeaderValue(headers, 'x-download-options') : null;
  if (!xdo) {
    out.push({
      title: 'X-Download-Options Not Set',
      description: 'Missing X-Download-Options for IE downloads',
      recommendation: "Add 'X-Download-Options: noopen' (legacy; IE-specific)",
      evidence: headerLine('X-Download-Options', xdo),
      checkFunction: 'checkDownloadOptions',
      severity: 'low'
    });
  }
  return out;
}

async function checkCrossDomainPolicies() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xpcdp = headers ? firstHeaderValue(headers, 'x-permitted-cross-domain-policies') : null;
  if (!xpcdp) {
    out.push({
      title: 'X-Permitted-Cross-Domain-Policies Not Set',
      description: 'Flash cross-domain policy not restricted',
      recommendation: "Add 'X-Permitted-Cross-Domain-Policies: none'",
      evidence: headerLine('X-Permitted-Cross-Domain-Policies', xpcdp),
      checkFunction: 'checkCrossDomainPolicies',
      severity: 'low'
    });
  }
  return out;
}

async function checkExpectCT() {
  const out = [];
  const isHttps = window.location && window.location.protocol === 'https:';
  if (!isHttps) return out;
  const { headers } = await getHeadersOrNull();
  const ect = headers ? firstHeaderValue(headers, 'expect-ct') : null;

  // Expect-CT is deprecated/removed in modern Chromium, so keep this informational.
  if (!ect) {
    out.push({
      title: 'Expect-CT Header Missing',
      description: 'Certificate Transparency monitoring not enabled (note: Expect-CT is deprecated in modern browsers)',
      recommendation: 'If you still rely on CT monitoring, implement it via platform/browser policy rather than Expect-CT.',
      evidence: headerLine('Expect-CT', ect),
      checkFunction: 'checkExpectCT',
      severity: 'low'
    });
  }
  return out;
}

async function checkExpires() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  if (!headers) return out;
  const expires = firstHeaderValue(headers, 'expires');
  const cacheControl = firstHeaderValue(headers, 'cache-control');

  // Avoid noise: only warn when the response is explicitly cacheable.
  const cc = String(cacheControl || '').toLowerCase();
  const explicitlyCacheable = /\bmax-age\s*=\s*\d+\b/.test(cc) || cc.includes('public');
  if (explicitlyCacheable && !expires) {
    out.push({
      title: 'Missing Expires Header',
      description: 'No explicit expiration time for cached content',
      recommendation: 'Set Expires header for cached resources',
      evidence: `${headerLine('Cache-Control', cacheControl)}\n${headerLine('Expires', expires)}`,
      checkFunction: 'checkExpires',
      severity: 'low'
    });
  }
  return out;
}

async function checkCOOP() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const coop = headers ? firstHeaderValue(headers, 'cross-origin-opener-policy') : null;
  if (!coop) {
    out.push({
      title: 'Missing Cross-Origin-Opener-Policy',
      description: 'No COOP header to isolate browsing context',
      recommendation: "Add 'Cross-Origin-Opener-Policy: same-origin'",
      evidence: headerLine('Cross-Origin-Opener-Policy', coop),
      checkFunction: 'checkCOOP'
    });
  }
  return out;
}

async function checkCOEP() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const coep = headers ? firstHeaderValue(headers, 'cross-origin-embedder-policy') : null;
  if (!coep) {
    out.push({
      title: 'Missing Cross-Origin-Embedder-Policy',
      description: 'No COEP header for cross-origin isolation',
      recommendation: "Add 'Cross-Origin-Embedder-Policy: require-corp'",
      evidence: headerLine('Cross-Origin-Embedder-Policy', coep),
      checkFunction: 'checkCOEP'
    });
  }
  return out;
}

async function checkCORP() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const corp = headers ? firstHeaderValue(headers, 'cross-origin-resource-policy') : null;
  if (!corp) {
    out.push({
      title: 'Missing Cross-Origin-Resource-Policy',
      description: 'No CORP header to protect resources',
      recommendation: "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site'",
      evidence: headerLine('Cross-Origin-Resource-Policy', corp),
      checkFunction: 'checkCORP'
    });
  }
  return out;
}

async function checkServerHeader() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const server = headers ? firstHeaderValue(headers, 'server') : null;
  if (server) {
    out.push({
      title: 'Server Header Information Disclosure',
      description: 'Server header reveals server type and version',
      recommendation: 'Remove or obscure Server header to hide server information',
      evidence: headerLine('Server', server),
      checkFunction: 'checkServerHeader'
    });
  }
  return out;
}

async function checkPoweredByHeader() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const xpb = headers ? firstHeaderValue(headers, 'x-powered-by') : null;
  if (xpb) {
    out.push({
      title: 'X-Powered-By Header Disclosure',
      description: 'X-Powered-By reveals technology stack',
      recommendation: 'Remove X-Powered-By header',
      evidence: headerLine('X-Powered-By', xpb),
      checkFunction: 'checkPoweredByHeader'
    });
  }
  return out;
}

async function checkAspNetVersion() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const v = headers ? firstHeaderValue(headers, 'x-aspnet-version') : null;
  if (v) {
    out.push({
      title: 'X-AspNet-Version Header Disclosure',
      description: 'X-AspNet-Version reveals ASP.NET version',
      recommendation: 'Remove X-AspNet-Version header',
      evidence: headerLine('X-AspNet-Version', v),
      checkFunction: 'checkAspNetVersion'
    });
  }
  return out;
}

async function checkMvcVersion() {
  const out = [];
  const { headers } = await getHeadersOrNull();
  const v = headers ? firstHeaderValue(headers, 'x-aspnetmvc-version') : null;
  if (v) {
    out.push({
      title: 'X-AspNetMvc-Version Header Disclosure',
      description: 'X-AspNetMvc-Version reveals MVC framework version',
      recommendation: 'Remove X-AspNetMvc-Version header',
      evidence: headerLine('X-AspNetMvc-Version', v),
      checkFunction: 'checkMvcVersion'
    });
  }
  return out;
}

async function checkResponseHeaders() {
  const issues = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;

  function trunc(text, maxLen) {
    const s = String(text || '');
    if (s.length <= maxLen) return s;
    return `${s.slice(0, Math.max(0, maxLen - 1))}…`;
  }

  function headerLine(name, value) {
    const n = String(name || '').trim();
    if (!value) return `Header ${n}: (missing)`;
    return `Header ${n}: ${trunc(value, 320)}`;
  }

  if (!headers) {
    issues.push({
      title: 'Response headers not available',
      description: 'Could not read HTTP response headers for this page. Some checks (CSP/HSTS/X-Frame-Options/Set-Cookie flags) may be incomplete.',
      severity: 'low',
      recommendation: 'Reload the page and rescan. Note: some restricted pages cannot be inspected.',
      evidence: snapshot && snapshot.url ? `URL: ${String(snapshot.url)}` : undefined
    });
    return issues;
  }

  const isHttps = window.location && window.location.protocol === 'https:';

  const hsts = firstHeaderValue(headers, 'strict-transport-security');
  if (isHttps && !hsts) {
    issues.push({
      title: 'Missing HSTS Header',
      description: 'Strict-Transport-Security header is missing. This can allow protocol downgrade attacks on first visit.',
      severity: 'high',
      recommendation: 'Set Strict-Transport-Security with a long max-age and includeSubDomains (and optionally preload).',
      evidence: headerLine('Strict-Transport-Security', hsts)
    });
  }

  const xfo = firstHeaderValue(headers, 'x-frame-options');
  const csp = allHeaderValues(headers, 'content-security-policy').join(' ');
  const hasFrameAncestors = /frame-ancestors\s+/i.test(csp);
  if (!xfo && !hasFrameAncestors) {
    issues.push({
      title: 'Clickjacking protection missing',
      description: 'Neither X-Frame-Options nor CSP frame-ancestors is present. The page may be embeddable in iframes.',
      severity: 'high',
      recommendation: 'Set X-Frame-Options (DENY/SAMEORIGIN) and/or add CSP frame-ancestors.',
      evidence: `${headerLine('X-Frame-Options', xfo)}\n${hasFrameAncestors ? 'CSP: frame-ancestors present' : 'CSP: frame-ancestors (missing)'}`
    });
  }

  const xcto = firstHeaderValue(headers, 'x-content-type-options');
  if (!xcto) {
    issues.push({
      title: 'Missing X-Content-Type-Options',
      description: 'X-Content-Type-Options is missing; browsers may MIME-sniff content types.',
      severity: 'medium',
      recommendation: 'Set X-Content-Type-Options: nosniff.',
      evidence: headerLine('X-Content-Type-Options', xcto)
    });
  }

  const rp = firstHeaderValue(headers, 'referrer-policy');
  if (!rp) {
    issues.push({
      title: 'Missing Referrer-Policy',
      description: 'Referrer-Policy is missing; URLs (including query params) may leak via the Referer header.',
      severity: 'low',
      recommendation: 'Set Referrer-Policy to strict-origin-when-cross-origin (or stricter if possible).',
      evidence: headerLine('Referrer-Policy', rp)
    });
  }

  const pp = firstHeaderValue(headers, 'permissions-policy');
  if (!pp) {
    issues.push({
      title: 'Missing Permissions-Policy',
      description: 'Permissions-Policy is missing; browser features are not explicitly restricted.',
      severity: 'low',
      recommendation: 'Add a Permissions-Policy header to restrict powerful browser features as needed.',
      evidence: headerLine('Permissions-Policy', pp)
    });
  }

  if (!csp) {
    issues.push({
      title: 'Missing Content-Security-Policy',
      description: 'Content-Security-Policy header is missing. CSP helps mitigate XSS and data injection.',
      severity: 'high',
      recommendation: 'Add a strict CSP header (avoid unsafe-inline/unsafe-eval; use nonces/hashes).',
      evidence: headerLine('Content-Security-Policy', csp)
    });
  } else {
    if (/unsafe-inline/i.test(csp)) {
      issues.push({
        title: 'Unsafe CSP: unsafe-inline',
        description: 'CSP allows unsafe-inline, which weakens XSS protection.',
        severity: 'medium',
        recommendation: 'Remove unsafe-inline and use nonces or hashes for inline scripts/styles.',
        evidence: headerLine('Content-Security-Policy', csp)
      });
    }
    if (/unsafe-eval/i.test(csp)) {
      issues.push({
        title: 'Unsafe CSP: unsafe-eval',
        description: 'CSP allows unsafe-eval, enabling dynamic code execution primitives.',
        severity: 'high',
        recommendation: 'Remove unsafe-eval and refactor code to avoid eval-like behavior.',
        evidence: headerLine('Content-Security-Policy', csp)
      });
    }
  }

  return issues;
}

function buildSessionCookieMatchers() {
  const exact = new Set([
    // Generic / Custom (very common)
    'session', 'sessionid', 'sid', 'sess', 'sessid', 'usersession', 'user_session', 'login', 'loginid',
    'auth', 'authid', 'auth_token', 'token', 'secure_token', 'security_token', 'identity', 'identity_token',
    'account', 'account_session',
    // PHP
    'phpsessid', 'phpsession', 'sessid', 'session_id',
    // Java (Servlets / JSP / Spring / Java EE)
    'jsessionid', 'jsession', 'spring_security_context', 'spring_session',
    // Python (Django / Flask / FastAPI / Starlette)
    'django', 'django_session', 'sessionid', 'flask_session', 'starlette_session',
    // Ruby on Rails
    '_session_id', 'rails_session',
    // ASP.NET / .NET
    'asp.net_sessionid', 'aspsessionid', '.aspxauth',
    '.aspnetcore.session', 'aspnetcore.session',
    '.aspnetcore.identity.application', 'aspnetcore.identity.application',
    // Node.js (Express / NestJS / AdonisJS)
    'connect.sid', 'express:sess', 'express-session', 'nest_session',
    'adonis-session', 'adonis-session-value',
    // Next.js / NextAuth
    'next-auth.session-token', 'next-auth.csrf-token', '__secure-next-auth.session-token',
    // OAuth / SSO / OpenID
    'oauth_token', 'oauth_token_secret', 'oauth_session', 'openid', 'openid_session',
    // Google / Microsoft / Enterprise SSO
    'hsid', 'ssid', 'sapisid', 'msisauth', 'msauth', 'aadauth',
    // JavaScript Frontend / SPA / API tokens
    'access_token', 'refresh_token', 'id_token', 'jwt', 'jwt_token', 'bearer', 'authorization',
    // CMS — Drupal
    'drupal_uid',
    // CMS — Joomla
    'joomla_user_state', 'joomla_session',
    // E-commerce — Magento
    'frontend', 'adminhtml', 'mage-cache-sessid',
    // Security / CSRF tokens
    'csrf', 'csrf_token', 'xsrf', 'xsrf_token', 'xsrf-token', 'anti_csrf', 'request_token',
    // "Remember Me" / Persistent Login
    'remember_me', 'rememberme', 'remember_token', 'persistent_login', 'keep_logged_in',
    // Legacy / Older Systems
    'cfid', 'cftoken', 'jservsessionid', 'websessid'
  ]);

  const prefixes = [
    'wordpress_logged_in_', 'wordpress_sec_', 'wp-settings-', 'wp-settings-time-',
    'joomla_',
    '_shopify_',
    '__secure-', '__host-',
    'aspsessionid'  // e.g. ASPSESSIONIDQWER…
  ];

  const contains = [
    'session', 'sess', 'auth', 'token', 'identity', 'login',
    'csrf', 'xsrf', 'remember', 'jwt', 'bearer'
  ];

  return { exact, prefixes, contains };
}

function isSessionLikeCookieName(name) {
  if (!name) return false;
  const n = String(name).trim();
  if (!n) return false;
  const lower = n.toLowerCase();
  const { exact, prefixes, contains } = buildSessionCookieMatchers();

  if (exact.has(lower)) return true;
  if (prefixes.some(p => lower.startsWith(p))) return true;
  if (/(^|[_.-])session($|[_.-])/i.test(n)) return true;
  if (/(^|[_.-])sid($|[_.-])/i.test(n)) return true;
  if (/(^|[_.-])auth($|[_.-])/i.test(n)) return true;
  if (/(^|[_.-])csrf($|[_.-])/i.test(n)) return true;
  if (/(^|[_.-])xsrf($|[_.-])/i.test(n)) return true;
  if (lower.startsWith('__secure-') || lower.startsWith('__host-')) return true;

  // Wildcard patterns: <app>_session, <app>_sid, <app>_auth
  if (/_session$/i.test(n) || /_sid$/i.test(n) || /_auth$/i.test(n)) return true;

  // Conservative fallback: if it contains a strong keyword
  if (contains.some(k => lower.includes(k))) return true;
  return false;
}

function parseSetCookie(setCookieValue) {
  const parts = String(setCookieValue || '').split(';').map(p => p.trim()).filter(Boolean);
  const first = parts.shift() || '';
  const eq = first.indexOf('=');
  const name = eq >= 0 ? first.slice(0, eq).trim() : first.trim();
  const attrs = Object.create(null);

  for (const p of parts) {
    const i = p.indexOf('=');
    if (i === -1) {
      attrs[p.toLowerCase()] = true;
    } else {
      const k = p.slice(0, i).trim().toLowerCase();
      const v = p.slice(i + 1).trim();
      attrs[k] = v;
    }
  }

  return { name, attrs, raw: String(setCookieValue || '') };
}

async function checkSessionCookiesFromResponse() {
  const issues = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  if (!headers) return issues;

  const setCookies = allHeaderValues(headers, 'set-cookie');
  if (!setCookies.length) return issues;

  const isHttps = window.location && window.location.protocol === 'https:';

  function redactSetCookie(line) {
    // Best-effort: redact the cookie value (before first ';'), keep name and attributes.
    // Example: "sid=abcdef...; Path=/; Secure".
    const s = String(line || '');
    const semi = s.indexOf(';');
    const head = semi === -1 ? s : s.slice(0, semi);
    const rest = semi === -1 ? '' : s.slice(semi);
    const eq = head.indexOf('=');
    if (eq === -1) return `Set-Cookie: ${s}`;
    const name = head.slice(0, eq);
    const value = head.slice(eq + 1);
    const trimmed = value.trim();
    const redacted = trimmed.length > 10 ? `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}` : trimmed;
    return `Set-Cookie: ${name}=${redacted}${rest}`;
  }

  for (const sc of setCookies) {
    const parsed = parseSetCookie(sc);
    const cookieName = parsed.name;
    if (!isSessionLikeCookieName(cookieName)) continue;

    const attrs = parsed.attrs;
    const hasHttpOnly = attrs['httponly'] === true;
    const hasSecure = attrs['secure'] === true;
    const sameSiteRaw = attrs['samesite'] ? String(attrs['samesite']).toLowerCase() : '';

    if (!hasHttpOnly) {
      issues.push({
        title: 'Session cookie missing HttpOnly',
        description: `Session-like cookie "${cookieName}" is set without HttpOnly, which increases risk of theft via XSS.`,
        severity: 'high',
        recommendation: 'Set the HttpOnly flag on session cookies.',
        evidence: redactSetCookie(parsed.raw)
      });
    }

    if (isHttps && !hasSecure) {
      issues.push({
        title: 'Session cookie missing Secure',
        description: `Session-like cookie "${cookieName}" is set without Secure on an HTTPS site. It may be sent over HTTP in downgrade scenarios.`,
        severity: 'high',
        recommendation: 'Set the Secure flag on session cookies (and ensure the site enforces HTTPS).',
        evidence: redactSetCookie(parsed.raw)
      });
    }

    if (!sameSiteRaw) {
      issues.push({
        title: 'Session cookie missing SameSite',
        description: `Session-like cookie "${cookieName}" is set without SameSite; this increases CSRF risk.`,
        severity: 'medium',
        recommendation: 'Set SameSite=Lax (or Strict where possible) for session cookies.',
        evidence: redactSetCookie(parsed.raw)
      });
    } else if (sameSiteRaw === 'none') {
      const sev = hasSecure ? 'medium' : 'high';
      issues.push({
        title: 'Session cookie uses SameSite=None',
        description: `Session-like cookie "${cookieName}" uses SameSite=None. This allows cross-site cookie sending and increases CSRF exposure.`,
        severity: sev,
        recommendation: 'Prefer SameSite=Lax/Strict for sessions. If SameSite=None is required, ensure Secure is set and protect with anti-CSRF tokens.',
        evidence: redactSetCookie(parsed.raw)
      });
    }

    const lowerName = String(cookieName || '').toLowerCase();
    if (lowerName.startsWith('__secure-') && !hasSecure) {
      issues.push({
        title: '__Secure- cookie missing Secure',
        description: `Cookie "${cookieName}" uses the __Secure- prefix but is missing the Secure attribute.`,
        severity: 'high',
        recommendation: 'If you use the __Secure- prefix, the cookie must include Secure and be set over HTTPS.',
        evidence: redactSetCookie(parsed.raw)
      });
    }

    if (lowerName.startsWith('__host-')) {
      const hasDomain = Object.prototype.hasOwnProperty.call(attrs, 'domain');
      const path = attrs['path'] ? String(attrs['path']) : '';
      const pathOk = path === '/';

      if (!hasSecure || hasDomain || !pathOk) {
        issues.push({
          title: '__Host- cookie prefix misuse',
          description: `Cookie "${cookieName}" uses the __Host- prefix but does not meet requirements (must be Secure, must NOT set Domain, and must set Path=/).`,
          severity: 'high',
          recommendation: 'Fix Set-Cookie attributes for __Host- cookies: Secure; Path=/; no Domain attribute.',
          evidence: redactSetCookie(parsed.raw)
        });
      }
    }
  }

  return issues;
}

async function checkCookieSameSite() {
  const out = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  if (!headers) return out;
  const setCookies = allHeaderValues(headers, 'set-cookie');
  if (!setCookies.length) return out;

  function redactSetCookie(line) {
    const s = String(line || '');
    const semi = s.indexOf(';');
    const head = semi === -1 ? s : s.slice(0, semi);
    const rest = semi === -1 ? '' : s.slice(semi);
    const eq = head.indexOf('=');
    if (eq === -1) return `Set-Cookie: ${s}`;
    const name = head.slice(0, eq);
    const value = head.slice(eq + 1).trim();
    const redacted = value.length > 10 ? `${value.slice(0, 4)}…${value.slice(-4)}` : value;
    return `Set-Cookie: ${name}=${redacted}${rest}`;
  }

  for (const sc of setCookies) {
    const parsed = parseSetCookie(sc);
    if (!isSessionLikeCookieName(parsed.name)) continue;
    const attrs = parsed.attrs;
    const sameSiteRaw = attrs['samesite'] ? String(attrs['samesite']).toLowerCase() : '';
    if (!sameSiteRaw) {
      out.push({
        title: 'Cookie SameSite Not Set',
        description: 'Cookies lack SameSite attribute (checked for session-like cookies only)',
        recommendation: 'Set SameSite=Strict or Lax for session cookies',
        evidence: redactSetCookie(parsed.raw),
        checkFunction: 'checkCookieSameSite',
        severity: 'high'
      });
    }
  }

  return out;
}

async function checkCookiePrefix() {
  const out = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  if (!headers) return out;
  const setCookies = allHeaderValues(headers, 'set-cookie');
  if (!setCookies.length) return out;

  const isHttps = window.location && window.location.protocol === 'https:';

  function redactSetCookie(line) {
    const s = String(line || '');
    const semi = s.indexOf(';');
    const head = semi === -1 ? s : s.slice(0, semi);
    const rest = semi === -1 ? '' : s.slice(semi);
    const eq = head.indexOf('=');
    if (eq === -1) return `Set-Cookie: ${s}`;
    const name = head.slice(0, eq);
    const value = head.slice(eq + 1).trim();
    const redacted = value.length > 10 ? `${value.slice(0, 4)}…${value.slice(-4)}` : value;
    return `Set-Cookie: ${name}=${redacted}${rest}`;
  }

  for (const sc of setCookies) {
    const parsed = parseSetCookie(sc);
    const cookieName = parsed.name;
    if (!isSessionLikeCookieName(cookieName)) continue;

    const lower = String(cookieName || '').toLowerCase();
    if (lower.startsWith('__host-') || lower.startsWith('__secure-')) continue;

    const attrs = parsed.attrs;
    const hasSecure = attrs['secure'] === true;
    // Conservative: only advise prefixes when the cookie is already intended to be secure.
    if (isHttps && hasSecure) {
      out.push({
        title: 'Cookie Prefix Not Used',
        description: 'Missing __Host- or __Secure- prefix (checked for session-like cookies only)',
        recommendation: 'Use __Host- prefix for critical cookies where possible (Secure; Path=/; no Domain)',
        evidence: redactSetCookie(parsed.raw),
        checkFunction: 'checkCookiePrefix',
        severity: 'medium'
      });
    }
  }

  return out;
}

async function checkCookieDomain() {
  const out = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  if (!headers) return out;
  const setCookies = allHeaderValues(headers, 'set-cookie');
  if (!setCookies.length) return out;

  function redactSetCookie(line) {
    const s = String(line || '');
    const semi = s.indexOf(';');
    const head = semi === -1 ? s : s.slice(0, semi);
    const rest = semi === -1 ? '' : s.slice(semi);
    const eq = head.indexOf('=');
    if (eq === -1) return `Set-Cookie: ${s}`;
    const name = head.slice(0, eq);
    const value = head.slice(eq + 1).trim();
    const redacted = value.length > 10 ? `${value.slice(0, 4)}…${value.slice(-4)}` : value;
    return `Set-Cookie: ${name}=${redacted}${rest}`;
  }

  for (const sc of setCookies) {
    const parsed = parseSetCookie(sc);
    const cookieName = parsed.name;
    if (!isSessionLikeCookieName(cookieName)) continue;
    const attrs = parsed.attrs;
    const domain = Object.prototype.hasOwnProperty.call(attrs, 'domain') ? String(attrs['domain'] || '') : '';
    if (domain) {
      out.push({
        title: 'Cookie Domain Too Broad',
        description: 'Cookie accessible to many subdomains (checked for session-like cookies only)',
        recommendation: 'Avoid setting Domain on session cookies (prefer host-only cookies).',
        evidence: redactSetCookie(parsed.raw),
        checkFunction: 'checkCookieDomain',
        severity: 'medium'
      });
    }
  }

  return out;
}

async function checkCookiePath() {
  const out = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  if (!headers) return out;
  const setCookies = allHeaderValues(headers, 'set-cookie');
  if (!setCookies.length) return out;

  function redactSetCookie(line) {
    const s = String(line || '');
    const semi = s.indexOf(';');
    const head = semi === -1 ? s : s.slice(0, semi);
    const rest = semi === -1 ? '' : s.slice(semi);
    const eq = head.indexOf('=');
    if (eq === -1) return `Set-Cookie: ${s}`;
    const name = head.slice(0, eq);
    const value = head.slice(eq + 1).trim();
    const redacted = value.length > 10 ? `${value.slice(0, 4)}…${value.slice(-4)}` : value;
    return `Set-Cookie: ${name}=${redacted}${rest}`;
  }

  // Keep this very conservative to avoid noise.
  for (const sc of setCookies) {
    const parsed = parseSetCookie(sc);
    const cookieName = parsed.name;
    if (!isSessionLikeCookieName(cookieName)) continue;
    const attrs = parsed.attrs;
    const path = Object.prototype.hasOwnProperty.call(attrs, 'path') ? String(attrs['path'] || '') : '';
    if (path === '/') {
      out.push({
        title: 'Cookie Path Too Broad',
        description: 'Cookie Path=/ when more specific path possible (checked for session-like cookies only)',
        recommendation: 'Use a more specific Path when feasible to reduce exposure.',
        evidence: redactSetCookie(parsed.raw),
        checkFunction: 'checkCookiePath',
        severity: 'low'
      });
    }
  }

  return out;
}

async function checkCookieOverflow() {
  const out = [];
  const snapshot = await getResponseHeadersSnapshot();
  const headers = snapshot && snapshot.headers ? snapshot.headers : null;
  if (!headers) return out;
  const setCookies = allHeaderValues(headers, 'set-cookie');
  if (!setCookies.length) return out;

  // Cookie size limits vary, but ~4096 bytes per cookie is a common practical limit.
  // Keep this low/noisy: only flag cookies that are clearly huge.
  const threshold = 4096;

  function redactSetCookie(line) {
    const s = String(line || '');
    const semi = s.indexOf(';');
    const head = semi === -1 ? s : s.slice(0, semi);
    const rest = semi === -1 ? '' : s.slice(semi);
    const eq = head.indexOf('=');
    if (eq === -1) return `Set-Cookie: ${s}`;
    const name = head.slice(0, eq);
    const value = head.slice(eq + 1).trim();
    const redacted = value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value;
    return `Set-Cookie: ${name}=${redacted}${rest}`;
  }

  for (const sc of setCookies) {
    const raw = String(sc || '');
    if (raw.length < threshold) continue;
    const parsed = parseSetCookie(raw);
    out.push({
      title: 'Cookie Overflow',
      description: 'Storing too much data in cookies',
      recommendation: 'Use server-side sessions or other storage; keep cookies minimal.',
      evidence: `${redactSetCookie(parsed.raw)}\nLength: ${raw.length} bytes`,
      checkFunction: 'checkCookieOverflow',
      severity: 'low'
    });
  }

  return out;
}

async function checkSameSiteCSRF() {
  // DB item is about CSRF risk from missing SameSite; reuse the cookie check.
  return checkCookieSameSite();
}

function sendProgress(scanId, current, total, stepLabel) {
  const percent = total ? Math.round((current / total) * 100) : 0;
  chrome.runtime.sendMessage({
    action: 'scanProgress',
    scanId,
    current,
    total,
    percent,
    step: stepLabel
  });
}

function getHighestSeverity(issues) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  let best = 'low';
  for (const issue of issues || []) {
    const sev = issue && issue.severity ? String(issue.severity).toLowerCase() : 'low';
    if ((rank[sev] || 0) > (rank[best] || 0)) best = sev;
  }
  return best;
}

function isElement(value) {
  return value && typeof value === 'object' && value.nodeType === Node.ELEMENT_NODE;
}

function cssSelectorForElement(el) {
  try {
    if (!el || !isElement(el)) return null;
    if (el.id) return `#${cssEscape(el.id)}`;

    const parts = [];
    let node = el;
    let depth = 0;
    while (node && isElement(node) && depth < 4) {
      const tag = node.tagName.toLowerCase();

      let part = tag;
      const classList = Array.from(node.classList || []).filter(Boolean).slice(0, 2);
      if (classList.length) {
        part += classList.map(c => `.${cssEscape(c)}`).join('');
      }

      const parent = node.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter(s => s.tagName === node.tagName);
        if (siblings.length > 1) {
          const idx = siblings.indexOf(node);
          if (idx >= 0) part += `:nth-of-type(${idx + 1})`;
        }
      }

      parts.unshift(part);
      node = node.parentElement;
      depth++;
    }

    return parts.join(' > ');
  } catch {
    return null;
  }
}

function cssEscape(value) {
  // Minimal CSS.escape fallback.
  return String(value).replace(/[^a-zA-Z0-9_-]/g, (m) => `\\${m}`);
}

function createBestEffortLocator() {
  let cached = null;

  function getCache() {
    if (cached) return cached;
    const html = document.documentElement ? document.documentElement.outerHTML : '';
    const lineStarts = [0];
    for (let i = 0; i < html.length; i++) {
      if (html.charCodeAt(i) === 10) {
        lineStarts.push(i + 1);
      }
    }
    cached = { html, lineStarts };
    return cached;
  }

  function posToLineCol(pos) {
    const { lineStarts } = getCache();
    if (pos == null || pos < 0) return null;

    // Binary search for last lineStart <= pos
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (lineStarts[mid] <= pos) lo = mid + 1;
      else hi = mid - 1;
    }
    const lineIndex = Math.max(0, hi);
    const line = lineIndex + 1;
    const column = (pos - lineStarts[lineIndex]) + 1;
    return { line, column };
  }

  function getLineText(line) {
    const { html, lineStarts } = getCache();
    if (!html) return '';
    const i = Number(line) - 1;
    if (!Number.isFinite(i) || i < 0 || i >= lineStarts.length) return '';
    const start = lineStarts[i];
    const end = (i + 1 < lineStarts.length) ? (lineStarts[i + 1] - 1) : html.length;
    return html.slice(start, end);
  }

  function findLineColForElement(el) {
    try {
      if (!el || !isElement(el)) return null;
      const { html } = getCache();
      if (!html) return null;

      const outer = el.outerHTML;
      if (!outer) return null;

      let idx = html.indexOf(outer);
      if (idx === -1 && el.id) {
        // fallback: find the start tag with id
        const tag = el.tagName.toLowerCase();
        const needle = `<${tag}`;
        let from = 0;
        while (true) {
          const start = html.indexOf(needle, from);
          if (start === -1) break;
          const end = html.indexOf('>', start);
          if (end === -1) break;
          const startTag = html.slice(start, end + 1);
          if (startTag.includes(`id="${el.id}"`) || startTag.includes(`id='${el.id}'`)) {
            idx = start;
            break;
          }
          from = end + 1;
        }
      }

      if (idx === -1) return null;
      return posToLineCol(idx);
    } catch {
      return null;
    }
  }

  function findLineColForTextInElement(el, needle) {
    try {
      if (!el || !isElement(el)) return null;
      const n = String(needle || '');
      if (!n) return null;

      const { html } = getCache();
      if (!html) return null;

      const outer = el.outerHTML;
      if (!outer) return null;

      const elementStart = html.indexOf(outer);
      if (elementStart === -1) return null;

      const inner = outer.indexOf(n);
      if (inner === -1) return null;

      return posToLineCol(elementStart + inner);
    } catch {
      return null;
    }
  }

  return { findLineColForElement, findLineColForTextInElement, getLineText };
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { performSecurityScanStepwise };
}
