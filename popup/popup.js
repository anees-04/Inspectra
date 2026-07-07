document.addEventListener('DOMContentLoaded', function() {
  const startScanBtn = document.getElementById('startScan');
  const rescanBtn = document.getElementById('rescan');
  const exportReportBtn = document.getElementById('exportReport');
  const resultsSection = document.getElementById('results');
  const loadingSection = document.getElementById('loading');
  const progressBar = document.getElementById('progress');
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  const progressMeta = document.getElementById('progressMeta');
  const progressLabel = document.getElementById('progressLabel');
  const loadingText = document.getElementById('loadingText');
  const toast = document.getElementById('toast');
  const themeToggle = document.getElementById('themeToggle');

  const authSection = document.getElementById('authSection');
  const authConfirm = document.getElementById('authConfirm');
  const scanHost = document.getElementById('scanHost');

  let activeHost = null;

  let lastScan = null;
  let activeScan = null;

  initTheme().catch(console.error);
  initAuthorizationGate().catch(console.error);

  startScanBtn.addEventListener('click', startScan);
  rescanBtn.addEventListener('click', startScan);
  exportReportBtn.addEventListener('click', exportReport);
  themeToggle.addEventListener('click', toggleTheme);

  chrome.runtime.onMessage.addListener((message, sender) => {
    if (!message || message.action !== 'scanProgress') return;
    if (!activeScan) return;
    if (message.scanId !== activeScan.scanId) return;
    if (!sender || !sender.tab || sender.tab.id !== activeScan.tabId) return;

    if (typeof message.percent === 'number') {
      setProgress(Math.max(0, Math.min(100, message.percent)), message.step || 'Scanning…');
    }
  });

  async function startScan() {
    if (!(await isAuthorizedForActiveTab())) {
      showToast('Confirmation required: please confirm you are authorized to scan this site.', 'error');
      return;
    }

    // Hide results and show loading
    resultsSection.style.display = 'none';
    loadingSection.style.display = 'block';
    progressBar.style.display = 'block';
    progressMeta.style.display = 'block';
    startScanBtn.style.display = 'none';
    toast.style.display = 'none';

    try {
      // Get current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tab || !tab.id || !tab.url) {
        throw new Error('No active tab found.');
      }

      const url = String(tab.url);
      const restrictedSchemes = ['chrome://', 'edge://', 'about:', 'chrome-extension://'];
      if (restrictedSchemes.some(s => url.startsWith(s))) {
        throw new Error('This page cannot be scanned due to browser restrictions. Open a normal website tab and try again.');
      }

      activeScan = {
        tabId: tab.id,
        scanId: crypto.randomUUID ? crypto.randomUUID() : String(Date.now())
      };

      loadingText.textContent = 'Preparing scan…';
      setProgress(0, 'Preparing scan…');

      await ensureScannerInjected(tab.id);

      loadingText.textContent = 'Scanning page…';
      setProgress(0, 'Starting checks…');

      const response = await chrome.tabs.sendMessage(tab.id, { action: 'scan', scanId: activeScan.scanId });
      const rawResults = (response && response.results) ? response.results : [];
      const scanResults = enrichIssuesFromDatabase(rawResults);

      lastScan = {
        url: tab.url,
        issues: scanResults,
        tabId: tab.id
      };

      setProgress(100, 'Complete');

      displayResults(scanResults);
      showToast(`Scan complete: ${scanResults.length} issue(s) found.`, 'success');

    } catch (error) {
      console.error('Scan error:', error);
      showToast(`Scan failed: ${error.message}`, 'error');
    } finally {
      loadingSection.style.display = 'none';
      progressBar.style.display = 'none';
      progressMeta.style.display = 'none';
      startScanBtn.style.display = 'block';
      activeScan = null;
    }
  }

  async function initAuthorizationGate() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab && tab.url ? String(tab.url) : '';
      const restrictedSchemes = ['chrome://', 'edge://', 'about:', 'chrome-extension://'];

      if (!url || restrictedSchemes.some(s => url.startsWith(s))) {
        // No valid site to confirm; keep scan disabled.
        activeHost = null;
        if (authSection) authSection.style.display = 'none';
        setScanEnabled(false);
        return;
      }

      let host = null;
      try {
        host = new URL(url).hostname;
      } catch (_) {
        host = null;
      }

      activeHost = host;
      if (scanHost) scanHost.textContent = host || 'this site';
      if (authSection) authSection.style.display = 'block';

      const key = storageKeyForHost(host);
      const stored = await chrome.storage.local.get([key]);
      const confirmed = Boolean(stored && stored[key]);
      if (authConfirm) authConfirm.checked = confirmed;
      setScanEnabled(confirmed);

      if (authConfirm) {
        authConfirm.addEventListener('change', async () => {
          const isChecked = Boolean(authConfirm.checked);
          setScanEnabled(isChecked);
          if (!host) return;
          await chrome.storage.local.set({ [storageKeyForHost(host)]: isChecked });
        });
      }
    } catch (_) {
      // Best effort; default to requiring confirmation.
      if (authSection) authSection.style.display = 'block';
      setScanEnabled(false);
    }
  }

  function storageKeyForHost(host) {
    return `authorizedScan:${String(host || '').toLowerCase()}`;
  }

  function setScanEnabled(enabled) {
    if (startScanBtn) startScanBtn.disabled = !enabled;
    if (rescanBtn) rescanBtn.disabled = !enabled;
  }

  async function isAuthorizedForActiveTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab && tab.url ? String(tab.url) : '';
      const restrictedSchemes = ['chrome://', 'edge://', 'about:', 'chrome-extension://'];
      if (!url || restrictedSchemes.some(s => url.startsWith(s))) return false;

      const host = new URL(url).hostname;
      const key = storageKeyForHost(host);
      const stored = await chrome.storage.local.get([key]);
      return Boolean(stored && stored[key]);
    } catch (_) {
      return false;
    }
  }

  function setProgress(percent, label) {
    progressText.textContent = `${percent}%`;
    progressFill.style.width = `${percent}%`;
    if (label) progressLabel.textContent = label;
  }

  function showToast(message, type) {
    toast.className = `toast ${type || ''}`.trim();
    toast.textContent = message;
    toast.style.display = 'block';

    window.clearTimeout(showToast._timer);
    showToast._timer = window.setTimeout(() => {
      toast.style.display = 'none';
    }, 3500);
  }

  async function ensureScannerInjected(tabId) {
    try {
      await chrome.tabs.sendMessage(tabId, { action: 'ping' });
      return;
    } catch (_) {
      // Content script not available (e.g., chrome:// pages, or not injected yet)
    }

    // Fallback: try to inject scanner scripts.
    await chrome.scripting.executeScript({
      target: { tabId },
      files: [
        'data/misconfigurations-category1.js',
        'data/misconfigurations-category2.js',
        'data/misconfigurations-category3.js',
        'data/misconfigurations-category4.js',
        'data/misconfigurations-category5.js',
        'data/misconfigurations-category6.js',
        'data/misconfigurations-category7.js',
        'data/misconfigurations-category8.js',
        'data/misconfigurations-category9.js',
        'data/misconfigurations-category10.js',
        'data/misconfigurations-index.js',
        'scripts/security-checks.js',
        'scripts/content.js'
      ]
    });

    // Confirm it is ready.
    await chrome.tabs.sendMessage(tabId, { action: 'ping' });
  }

  async function initTheme() {
    const stored = await chrome.storage.local.get(['theme']);
    const theme = stored.theme || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    applyTheme(theme);
  }

  function applyTheme(theme) {
    const normalized = theme === 'dark' ? 'dark' : 'light';
    document.documentElement.dataset.theme = normalized;
    themeToggle.textContent = normalized === 'dark' ? 'Dark' : 'Light';
  }

  async function toggleTheme() {
    const current = document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    await chrome.storage.local.set({ theme: next });
  }

  function displayResults(scanResults) {
    resultsSection.style.display = 'block';

    // Update statistics
    const criticalCount = scanResults.filter(i => normalizeSeverity(i && i.severity) === 'critical').length;
    const highCount = scanResults.filter(i => normalizeSeverity(i && i.severity) === 'high').length;
    const mediumCount = scanResults.filter(i => normalizeSeverity(i && i.severity) === 'medium').length;
    const lowCount = scanResults.filter(i => normalizeSeverity(i && i.severity) === 'low').length;

    document.getElementById('criticalCount').textContent = criticalCount;
    document.getElementById('highCount').textContent = highCount;
    document.getElementById('mediumCount').textContent = mediumCount;
    document.getElementById('lowCount').textContent = lowCount;

    // Display issues
    const issuesList = document.getElementById('issuesList');
    issuesList.innerHTML = '';

    if (scanResults.length === 0) {
      issuesList.innerHTML = '<p style="text-align: center; color: #4caf50; padding: 20px;">✓ No security issues detected! Great job!</p>';
    } else {
      const rank = { critical: 4, high: 3, medium: 2, low: 1 };
      const sorted = [...scanResults].sort((a, b) => {
        const sa = normalizeSeverity(a && a.severity);
        const sb = normalizeSeverity(b && b.severity);
        const diff = (rank[sb] || 0) - (rank[sa] || 0);
        if (diff !== 0) return diff;
        const ta = String((a && a.title) || '');
        const tb = String((b && b.title) || '');
        return ta.localeCompare(tb);
      });

      sorted.forEach(issue => {
        const issueElement = createIssueElement(issue);
        issuesList.appendChild(issueElement);
      });
    }
  }

  function enrichIssuesFromDatabase(issues) {
    if (!Array.isArray(issues)) return [];
    if (typeof MISCONFIG_DB === 'undefined' || !MISCONFIG_DB || !Array.isArray(MISCONFIG_DB.all)) {
      return issues;
    }

    const titleToItem = new Map();
    for (const item of MISCONFIG_DB.all) {
      if (!item || !item.title) continue;
      const key = normalizeTitle(item.title);
      if (!titleToItem.has(key)) titleToItem.set(key, item);
    }

    return issues.map((issue) => {
      if (!issue || !issue.title) return issue;
      let match = null;
      if (
        issue.checkFunction &&
        MISCONFIG_DB.byCheckFunction &&
        typeof MISCONFIG_DB.byCheckFunction.get === 'function'
      ) {
        const candidates = MISCONFIG_DB.byCheckFunction.get(issue.checkFunction);
        if (Array.isArray(candidates) && candidates.length) {
          const wanted = normalizeTitle(issue.title);
          match = candidates.find(c => c && c.title && normalizeTitle(c.title) === wanted) || candidates[0];
        }
      }

      if (!match) {
        match = titleToItem.get(normalizeTitle(issue.title)) || null;
      }
      if (!match) return issue;

      // Prefer scanner's live description/recommendation if present; otherwise fall back to DB.
      return {
        ...issue,
        misconfigId: match.id ?? issue.misconfigId,
        category: match.category ?? issue.category,
        cwe: match.cwe ?? issue.cwe,
        owasp: match.owasp ?? issue.owasp,
        recommendation: (issue.recommendation && String(issue.recommendation).trim())
          ? issue.recommendation
          : (match.recommendation ?? issue.recommendation)
      };
    });
  }

  function normalizeTitle(title) {
    return String(title).trim().toLowerCase().replace(/\s+/g, ' ');
  }

  function normalizeSeverity(severity) {
    const s = String(severity || '').trim().toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
    return 'low';
  }

  function createIssueElement(issue) {
    const div = document.createElement('div');
    const severity = normalizeSeverity(issue && issue.severity);
    div.className = `issue-item ${severity}`;

    const metaParts = [];
    if (issue.misconfigId) metaParts.push(`<span class="issue-meta">ID ${escapeHtml(String(issue.misconfigId))}</span>`);
    if (issue.cwe) metaParts.push(`<span class="issue-meta">${escapeHtml(String(issue.cwe))}</span>`);
    if (issue.owasp) metaParts.push(`<span class="issue-meta">${escapeHtml(String(issue.owasp))}</span>`);
    if (issue.location && typeof issue.location.line === 'number') {
      const col = (issue.location && typeof issue.location.column === 'number') ? `:${issue.location.column}` : '';
      metaParts.push(`<span class="issue-meta">Line ${escapeHtml(String(issue.location.line))}${escapeHtml(col)}</span>`);
    }
    const metaHtml = metaParts.length ? `<div class="issue-metadata">${metaParts.join('')}</div>` : '';

    const locationDetails = (issue.location && (issue.location.selector || issue.location.line))
      ? `
        <div class="issue-location">
          <div class="location-title">📍 Location</div>
          <div class="location-body">
            ${issue.location.line ? `<div>Page source: <strong>Line ${escapeHtml(String(issue.location.line))}${issue.location.column ? ':' + escapeHtml(String(issue.location.column)) : ''}</strong></div>` : ''}
            ${issue.location.selector ? `<div class="location-selector">${escapeHtml(String(issue.location.selector))}</div>` : ''}
          </div>
        </div>
      `
      : '';

    const highlightToken = (() => {
      if (issue && issue.highlight && String(issue.highlight).trim().length > 0) return String(issue.highlight);
      const title = String((issue && issue.title) || '').toLowerCase();
      if (title.includes('mixed content')) return 'http:';
      if (title.includes('external link without rel')) return '<a';
      if (title.includes('javascript urls') || title.includes('javascript:')) return 'javascript:';
      if (title.includes('inline scripts')) return '<script';
      if (title.includes('inline event handlers')) return 'on';
      return '';
    })();

    const evidenceHtml = (issue && issue.evidence)
      ? `
        <div class="issue-evidence">
          <div class="evidence-title">🔎 Evidence</div>
          <div class="evidence-body">${escapeHtml(String(issue.evidence))}</div>
        </div>
      `
      : '';

    const codeContextShell = (issue.location && (typeof issue.location.line === 'number' || issue.location.selector))
      ? `
        <div class="code-context"
             ${typeof issue.location.line === 'number' ? `data-line="${escapeHtml(String(issue.location.line))}"` : ''}
             ${issue.location.selector ? `data-selector="${escapeHtml(String(issue.location.selector))}"` : ''}
             ${highlightToken ? `data-highlight="${escapeHtml(String(highlightToken))}"` : ''}
             data-loaded="0">
          <div class="code-context-title">🧾 Code context</div>
          <div class="code-context-body">(Click to load)</div>
        </div>
      `
      : '';
    
    div.innerHTML = `
      <div class="issue-header">
        <span class="issue-title">${escapeHtml(issue.title || 'Untitled Issue')}</span>
        <span class="issue-severity ${severity}">${escapeHtml(severity)}</span>
      </div>
      ${metaHtml}
      <div class="issue-description">${escapeHtml(issue.description || '')}</div>
      <div class="issue-recommendation">
        ${locationDetails}
        ${codeContextShell}
        ${evidenceHtml}
        <div class="recommendation-title">💡 Recommendation:</div>
        <div>${escapeHtml(issue.recommendation || '')}</div>
      </div>
    `;

    div.addEventListener('click', () => {
      div.classList.toggle('expanded');

      // Lazy-load source context only when expanded.
      if (!div.classList.contains('expanded')) return;
      const ctx = div.querySelector('.code-context');
      if (!ctx) return;
      if (ctx.getAttribute('data-loaded') === '1') return;
      void loadCodeContext(ctx).catch(() => {
        // best-effort
      });
    });

    return div;
  }

  async function loadCodeContext(ctxEl) {
    try {
      const lineStr = ctxEl.getAttribute('data-line');
      const line = Number(lineStr);
      const selector = ctxEl.getAttribute('data-selector');
      const highlight = ctxEl.getAttribute('data-highlight');

      const hasLine = Number.isFinite(line) && line >= 1;
      const hasSelector = selector && String(selector).trim().length > 0;
      if (!hasLine && !hasSelector) return;

      const tabId = lastScan && lastScan.tabId;
      if (!tabId) {
        ctxEl.querySelector('.code-context-body').textContent = 'Unable to load context (no tab).';
        ctxEl.setAttribute('data-loaded', '1');
        return;
      }

      ctxEl.querySelector('.code-context-body').textContent = 'Loading…';

      const mode = hasSelector ? 'element' : 'line';
      const resp = await chrome.tabs.sendMessage(tabId, {
        action: 'getSourceContext',
        ...(hasLine ? { line } : {}),
        ...(!hasLine && hasSelector ? { selector: String(selector) } : {}),
        ...(hasSelector ? { selector: String(selector) } : {}),
        mode,
        highlight: highlight ? String(highlight) : undefined,
        radius: 0
      });
      if (!resp || resp.ok !== true) {
        ctxEl.querySelector('.code-context-body').textContent = 'Unable to load context.';
        ctxEl.setAttribute('data-loaded', '1');
        return;
      }

      // Prefer element-based context (much more direct than a full HTML line).
      if (resp.mode === 'element' && typeof resp.openTag === 'string') {
        const where = (typeof resp.line === 'number')
          ? `Line ${escapeHtml(String(resp.line))}${typeof resp.column === 'number' ? ':' + escapeHtml(String(resp.column)) : ''}`
          : 'Element';

        const rawLine = (typeof resp.contextLine === 'string' && resp.contextLine.trim().length > 0)
          ? resp.contextLine
          : resp.openTag;

        let openTagEsc = escapeHtml(rawLine);
        if (highlight && String(highlight).length > 0) {
          openTagEsc = markToken(openTagEsc, String(highlight));
        }

        ctxEl.querySelector('.code-context-body').innerHTML = `
          <div class="code-one">
            <div class="code-one-meta">${where}</div>
            <div class="code-one-line code-line-target"><span class="code-txt">${openTagEsc}</span></div>
          </div>
        `;
        ctxEl.setAttribute('data-loaded', '1');
        return;
      }

      if (!Array.isArray(resp.snippet) || resp.snippet.length === 0) {
        ctxEl.querySelector('.code-context-body').textContent = 'Unable to load context.';
        ctxEl.setAttribute('data-loaded', '1');
        return;
      }

      // Line-based fallback: show only the target line.
      const row = resp.snippet.find(r => r && r.isTarget) || resp.snippet[0];
      const ln = escapeHtml(String(row.line));
      let text = escapeHtml(String(row.text ?? ''));
      if (highlight && String(highlight).length > 0) {
        text = markToken(text, String(highlight));
      }
      ctxEl.querySelector('.code-context-body').innerHTML = `
        <div class="code-one">
          <div class="code-one-meta">Line ${ln}${resp.column ? ':' + escapeHtml(String(resp.column)) : ''}</div>
          <div class="code-one-line code-line-target"><span class="code-txt">${text}</span></div>
        </div>
      `;
      ctxEl.setAttribute('data-loaded', '1');
    } catch (_) {
      try {
        const body = ctxEl.querySelector('.code-context-body');
        if (body) body.textContent = 'Unable to load context.';
        ctxEl.setAttribute('data-loaded', '1');
      } catch {
        // ignore
      }
    }
  }

  function exportReport() {
    const issues = (lastScan && Array.isArray(lastScan.issues)) ? lastScan.issues : [];

    const report = {
      timestamp: new Date().toISOString(),
      url: lastScan ? lastScan.url : null,
      issues,
      summary: {
        critical: parseInt(document.getElementById('criticalCount').textContent),
        high: parseInt(document.getElementById('highCount').textContent),
        medium: parseInt(document.getElementById('mediumCount').textContent),
        low: parseInt(document.getElementById('lowCount').textContent)
      },
      misconfigurationDatabase: {
        total: (typeof MISCONFIG_DB !== 'undefined' && MISCONFIG_DB && typeof MISCONFIG_DB.total === 'number')
          ? MISCONFIG_DB.total
          : null
      }
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${Date.now()}.json`;
    a.click();
  }

  function escapeHtml(str) {
    return String(str)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function escapeRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function markToken(escapedText, token) {
    const t = String(token);
    if (!t) return escapedText;

    // `escapedText` is already HTML-escaped; token should be matched against the escaped text too.
    const escapedToken = escapeHtml(t);
    if (!escapedToken) return escapedText;

    const re = new RegExp(escapeRegExp(escapedToken), 'gi');
    return String(escapedText).replace(re, (m) => `<mark class="code-mark">${m}</mark>`);
  }
});
