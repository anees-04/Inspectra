// Security Checks Implementation
// This file contains all the security scanning logic

// ==================== HTTP HEADERS CHECKS ====================
function checkHTTPHeaders() {
  const issues = [];
  
  // Check for missing security headers
  const securityHeaders = {
    'strict-transport-security': {
      title: 'Missing HSTS Header',
      description: 'HTTP Strict Transport Security (HSTS) header not found. Site may be vulnerable to SSL stripping attacks.',
      recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" header.',
      severity: 'high'
    },
    'x-frame-options': {
      title: 'Missing X-Frame-Options Header',
      description: 'X-Frame-Options header not found. Site may be vulnerable to clickjacking attacks.',
      recommendation: 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header.',
      severity: 'high'
    },
    'x-content-type-options': {
      title: 'Missing X-Content-Type-Options Header',
      description: 'X-Content-Type-Options header not found. Browser may MIME-sniff content.',
      recommendation: 'Add "X-Content-Type-Options: nosniff" header.',
      severity: 'medium'
    },
    'x-xss-protection': {
      title: 'Missing X-XSS-Protection Header',
      description: 'X-XSS-Protection header not found or disabled.',
      recommendation: 'Add "X-XSS-Protection: 1; mode=block" header.',
      severity: 'medium'
    },
    'content-security-policy': {
      title: 'Missing Content-Security-Policy Header',
      description: 'CSP header not found. Site lacks defense against XSS and data injection attacks.',
      recommendation: 'Implement a strict Content-Security-Policy header.',
      severity: 'high'
    },
    'referrer-policy': {
      title: 'Missing Referrer-Policy Header',
      description: 'Referrer-Policy header not found. Sensitive information may leak through referrer.',
      recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" or stricter.',
      severity: 'low'
    },
    'permissions-policy': {
      title: 'Missing Permissions-Policy Header',
      description: 'Permissions-Policy (Feature-Policy) header not found.',
      recommendation: 'Add Permissions-Policy header to control browser features.',
      severity: 'low'
    }
  };

  // Note: We can't directly access HTTP headers from content script
  // This is a limitation - we'll check meta tags and simulate header checks
  
  // Check for CSP via meta tag
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!cspMeta) {
    issues.push({
      title: 'Missing Content-Security-Policy',
      description: 'No Content-Security-Policy found (checked via meta tag). Site may be vulnerable to XSS attacks.',
      recommendation: 'Implement CSP via HTTP header or meta tag: <meta http-equiv="Content-Security-Policy" content="default-src \'self\'">',
      severity: 'high'
    });
  } else {
    // Check CSP configuration
    const cspContent = cspMeta.getAttribute('content');
    if (cspContent.includes('unsafe-inline')) {
      issues.push({
        title: 'Unsafe CSP Configuration',
        description: 'CSP allows unsafe-inline scripts, weakening XSS protection.',
        recommendation: 'Remove "unsafe-inline" and use nonces or hashes for inline scripts.',
        severity: 'medium'
      });
    }
    if (cspContent.includes('unsafe-eval')) {
      issues.push({
        title: 'Dangerous CSP eval() Permission',
        description: 'CSP allows unsafe-eval, enabling dynamic code execution.',
        recommendation: 'Remove "unsafe-eval" from CSP directive.',
        severity: 'high'
      });
    }
  }

  // Check for X-Frame-Options via iframe detection
  if (window.self === window.top) {
    // Try to detect if framing is possible
    const frame = document.createElement('iframe');
    frame.style.display = 'none';
    frame.src = window.location.href;
    try {
      document.body.appendChild(frame);
      issues.push({
        title: 'Clickjacking Protection Missing',
        description: 'Page can be embedded in iframes, vulnerable to clickjacking.',
        recommendation: 'Set X-Frame-Options: DENY or use CSP frame-ancestors directive.',
        severity: 'high'
      });
      document.body.removeChild(frame);
    } catch (e) {
      // Frame protection might be present
    }
  }

  return issues;
}

// ==================== COOKIE SECURITY CHECKS ====================
function checkCookieSecurity() {
  const issues = [];
  const cookies = document.cookie.split(';');

  if (cookies.length === 0 || (cookies.length === 1 && cookies[0].trim() === '')) {
    // No cookies, can't check
    return issues;
  }

  // Check for insecure cookies
  cookies.forEach(cookie => {
    const cookieName = cookie.split('=')[0].trim();
    if (cookieName) {
      // Note: We can't check HttpOnly, Secure, or SameSite from JavaScript
      // These would need to be checked server-side
      issues.push({
        title: `Cookie Security Flags Unknown: ${cookieName}`,
        description: `Cookie "${cookieName}" flags cannot be verified from client-side. Ensure Secure, HttpOnly, and SameSite attributes are set.`,
        recommendation: 'Set cookies with Secure, HttpOnly, and SameSite=Strict or SameSite=Lax flags.',
        severity: 'medium'
      });
    }
  });

  // Check if cookies are set over HTTP
  if (window.location.protocol === 'http:') {
    issues.push({
      title: 'Cookies Set Over Insecure Connection',
      description: 'Cookies are being set over HTTP instead of HTTPS.',
      recommendation: 'Use HTTPS for all connections and set Secure flag on cookies.',
      severity: 'critical'
    });
  }

  // Check for session cookie without proper naming
  const sensitiveKeywords = [
    'session', 'sess', 'sid', 'auth', 'token', 'jwt', 'bearer', 'identity', 'login',
    'csrf', 'xsrf', 'remember', 'oauth', 'openid', 'phpsessid', 'jsessionid',
    'connect.sid', 'express', 'django', 'flask', 'rails', 'aspnet', 'shopify',
    'wordpress', 'drupal', 'joomla', 'magento', 'adonis', 'nest_session',
    'cfid', 'cftoken', 'hsid', 'ssid', 'sapisid', 'msisauth', 'msauth', 'aadauth'
  ];
  cookies.forEach(cookie => {
    const cookieName = cookie.split('=')[0].trim();
    const lower = cookieName.toLowerCase();
    const isSensitive = sensitiveKeywords.some(k => lower.includes(k))
      || lower.startsWith('__secure-') || lower.startsWith('__host-')
      || lower.startsWith('_shopify_') || lower.startsWith('wp-settings');
    if (isSensitive) {
      issues.push({
        title: `Sensitive Cookie Detected: ${cookieName}`,
        description: `Cookie with sensitive name "${cookieName}" detected. Ensure proper security flags.`,
        recommendation: 'Use HttpOnly, Secure, SameSite=Strict, and consider using __Secure- or __Host- prefix.',
        severity: 'high'
      });
    }
  });

  return issues;
}

// ==================== CONTENT SECURITY CHECKS ====================
function checkContentSecurity() {
  const issues = [];

  // Check for mixed content
  if (window.location.protocol === 'https:') {
    const insecureElements = Array.from(document.querySelectorAll('[src^="http:"], [href^="http:"]'));
    for (const el of insecureElements) {
      const src = el.getAttribute('src');
      const href = el.getAttribute('href');
      const url = (src && src.startsWith('http:')) ? src : (href && href.startsWith('http:')) ? href : null;
      if (!url) continue;
      issues.push({
        title: 'Mixed Content Detected',
        description: `Element loads an insecure resource over HTTP: ${url}`,
        recommendation: 'Use HTTPS for all resources. Prefer upgrading to https: and ensure the resource supports TLS.',
        severity: 'high',
        highlight: 'http:',
        element: el
      });
    }
  }

  // Check for inline scripts
  const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'));
  inlineScripts.forEach((script, idx) => {
    const typeAttr = (script.getAttribute('type') || '').toLowerCase();
    const isJsType = typeAttr === '' || typeAttr === 'text/javascript' || typeAttr === 'application/javascript' || typeAttr === 'module';
    const hasCode = (script.textContent || '').trim().length > 0;
    if (!isJsType || !hasCode) return;
    issues.push({
      title: `Inline Script Detected (Script ${idx + 1})`,
      description: 'Inline <script> detected. Inline scripts increase XSS attack surface and often require unsafe-inline CSP exceptions.',
      recommendation: 'Move scripts to external files and use CSP with nonces/hashes for any required inline code.',
      severity: 'medium',
      highlight: '<script',
      element: script
    });
  });

  // Check for inline event handlers
  const elementsWithHandlers = Array.from(document.querySelectorAll('*'));
  for (const el of elementsWithHandlers) {
    if (!el || !el.attributes) continue;
    for (const attr of Array.from(el.attributes)) {
      if (!attr || !attr.name) continue;
      const name = String(attr.name).toLowerCase();
      if (!name.startsWith('on')) continue;
      const value = String(attr.value || '').trim();
      if (!value) continue;
      issues.push({
        title: 'Inline Event Handler Detected',
        description: `Inline event handler "${name}" detected. Inline handlers are executable JS and often force weaker CSP (unsafe-inline).`,
        recommendation: 'Replace inline handlers with addEventListener() and use a strict CSP.',
        severity: 'medium',
        highlight: name,
        element: el
      });
    }
  }

  // Check for javascript: URLs
  const javascriptLinks = Array.from(document.querySelectorAll('a[href^="javascript:"]'));
  for (const a of javascriptLinks) {
    issues.push({
      title: 'JavaScript URL Detected',
      description: `Link uses javascript: URL, which executes code in a dangerous context: ${(a.getAttribute('href') || '').slice(0, 160)}`,
      recommendation: 'Replace javascript: URLs with safe event listeners and normal navigation URLs.',
      severity: 'medium',
      highlight: 'javascript:',
      element: a
    });
  }

  return issues;
}

// ==================== FORM SECURITY CHECKS ====================
function checkFormSecurity() {
  const issues = [];
  const forms = document.querySelectorAll('form');

  forms.forEach((form, index) => {
    // Check for forms submitting to HTTP
    const action = form.getAttribute('action') || '';
    if (action.startsWith('http:')) {
      issues.push({
        title: `Form ${index + 1} Submits Over HTTP`,
        description: 'Form submits data over unencrypted HTTP connection.',
        recommendation: 'Use HTTPS for form submission URLs.',
        severity: 'critical',
        element: form
      });
    }

    // Check for password fields without autocomplete=off
    const passwordFields = form.querySelectorAll('input[type="password"]');
    passwordFields.forEach((field, fieldIndex) => {
      const autocomplete = field.getAttribute('autocomplete');
      
      // Check for missing autocomplete
      if (!field.name || field.name.length < 3) {
        issues.push({
          title: `Weak Password Field Name`,
          description: `Password field ${fieldIndex + 1} in form ${index + 1} has weak or missing name attribute.`,
          recommendation: 'Use descriptive names like "password" or "current-password" for password fields.',
          severity: 'low',
          element: field
        });
      }
    });

    // Check for forms without CSRF protection
    const csrfToken = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
    if (!csrfToken && (form.method.toLowerCase() === 'post' || !form.method)) {
      issues.push({
        title: `Form ${index + 1} Missing CSRF Token`,
        description: 'POST form does not appear to have CSRF protection.',
        recommendation: 'Add a CSRF token field to all state-changing forms.',
        severity: 'high',
        element: form
      });
    }

    // Check for sensitive data fields
    const sensitiveFields = form.querySelectorAll('input[type="password"], input[name*="card"], input[name*="ssn"], input[name*="credit"]');
    if (sensitiveFields.length > 0 && window.location.protocol === 'http:') {
      issues.push({
        title: `Sensitive Data Form Over HTTP`,
        description: `Form ${index + 1} contains sensitive fields but is on an HTTP page.`,
        recommendation: 'Always use HTTPS for pages with sensitive data forms.',
        severity: 'critical'
      });
    }

    // Check for file upload fields
    const fileFields = form.querySelectorAll('input[type="file"]');
    if (fileFields.length > 0) {
      issues.push({
        title: `File Upload in Form ${index + 1}`,
        description: 'File upload detected. Ensure proper validation and virus scanning.',
        recommendation: 'Validate file types, size limits, scan for malware, and store outside web root.',
        severity: 'high'
      });
    }
  });

  return issues;
}

// ==================== XSS CHECKS ====================
function checkXSS() {
  const issues = [];

  function trunc(text, maxLen) {
    const s = String(text || '');
    if (s.length <= maxLen) return s;
    return `${s.slice(0, Math.max(0, maxLen - 1))}…`;
  }

  function stripJsStringsAndComments(source) {
    // Lightweight lexer to reduce false positives (e.g., "eval(" inside strings/comments).
    // Not a full JS parser, but good enough for scanner heuristics.
    let out = '';
    let i = 0;
    let state = 'code';
    while (i < source.length) {
      const ch = source[i];
      const next = i + 1 < source.length ? source[i + 1] : '';

      if (state === 'code') {
        if (ch === '/' && next === '/') {
          state = 'line_comment';
          out += '  ';
          i += 2;
          continue;
        }
        if (ch === '/' && next === '*') {
          state = 'block_comment';
          out += '  ';
          i += 2;
          continue;
        }
        if (ch === "'") { state = 'single_quote'; out += ' '; i++; continue; }
        if (ch === '"') { state = 'double_quote'; out += ' '; i++; continue; }
        if (ch === '`') { state = 'template'; out += ' '; i++; continue; }

        out += ch;
        i++;
        continue;
      }

      if (state === 'line_comment') {
        if (ch === '\n') {
          state = 'code';
          out += '\n';
        } else {
          out += ' ';
        }
        i++;
        continue;
      }

      if (state === 'block_comment') {
        if (ch === '*' && next === '/') {
          state = 'code';
          out += '  ';
          i += 2;
        } else {
          out += ch === '\n' ? '\n' : ' ';
          i++;
        }
        continue;
      }

      if (state === 'single_quote') {
        if (ch === '\\') { out += '  '; i += 2; continue; }
        if (ch === "'") { state = 'code'; out += ' '; i++; continue; }
        out += ch === '\n' ? '\n' : ' ';
        i++;
        continue;
      }

      if (state === 'double_quote') {
        if (ch === '\\') { out += '  '; i += 2; continue; }
        if (ch === '"') { state = 'code'; out += ' '; i++; continue; }
        out += ch === '\n' ? '\n' : ' ';
        i++;
        continue;
      }

      if (state === 'template') {
        if (ch === '\\') { out += '  '; i += 2; continue; }
        if (ch === '`') { state = 'code'; out += ' '; i++; continue; }
        out += ch === '\n' ? '\n' : ' ';
        i++;
        continue;
      }
    }
    return out;
  }

  function getExecutableJsSnippets() {
    const snippets = [];

    // Inline scripts only (avoid scanning the whole HTML, which causes false positives).
    document.querySelectorAll('script').forEach((s) => {
      const typeAttr = (s.getAttribute('type') || '').toLowerCase();
      const isJsType = typeAttr === '' || typeAttr === 'text/javascript' || typeAttr === 'application/javascript' || typeAttr === 'module';
      if (!isJsType) return;
      if (s.src) return;
      const code = s.textContent || '';
      if (code.trim().length > 0) snippets.push({ kind: 'inline-script', el: s, code });
    });

    // Inline event handlers (executable JS)
    document.querySelectorAll('*').forEach((el) => {
      for (const attr of Array.from(el.attributes || [])) {
        if (!attr || !attr.name) continue;
        if (attr.name.toLowerCase().startsWith('on') && attr.value) {
          snippets.push({ kind: 'event-handler', el, attrName: attr.name, code: String(attr.value) });
        }
        if (attr.name.toLowerCase() === 'href' && typeof attr.value === 'string' && attr.value.trim().toLowerCase().startsWith('javascript:')) {
          snippets.push({ kind: 'javascript-url', el, attrName: 'href', code: String(attr.value) });
        }
      }
    });

    return snippets;
  }

  function extractEvidenceLine(text, matchIndex) {
    const idx = Math.max(0, Math.min(String(text || '').length, Number(matchIndex) || 0));
    const s = String(text || '');
    const start = s.lastIndexOf('\n', idx - 1) + 1;
    const endRaw = s.indexOf('\n', idx);
    const end = endRaw === -1 ? s.length : endRaw;
    return s.slice(start, end).trim().slice(0, 260);
  }

  // Check for potential reflected XSS via URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  const params = Array.from(urlParams.entries());
  
  params.forEach(([key, value]) => {
    // Check if parameter value appears in the page
    if (document.body.innerHTML.includes(value) && value.length > 2) {
      issues.push({
        title: 'Potential Reflected XSS',
        description: `URL parameter "${key}" value appears in page content without obvious encoding.`,
        recommendation: 'Always encode/escape user input before rendering in HTML. Use context-appropriate encoding.',
        severity: 'critical',
        evidence: `URL param: ${key}=${trunc(value, 160)}`
      });
    }

    // Check for dangerous patterns in URL
    const dangerousPatterns = ['<script', 'javascript:', 'onerror=', 'onclick=', '<img', '<iframe'];
    dangerousPatterns.forEach(pattern => {
      if (value.toLowerCase().includes(pattern)) {
        issues.push({
          title: 'XSS Payload Pattern in URL',
          description: `Suspicious pattern "${pattern}" found in URL parameter "${key}".`,
          recommendation: 'Implement input validation and sanitization. Reject requests with XSS patterns.',
          severity: 'critical',
          evidence: `URL param: ${key}=${trunc(value, 160)}`
        });
      }
    });
  });

  // Check for DOM XSS sinks
  const dangerousProperties = ['innerHTML', 'outerHTML', 'document.write'];
  const scripts = document.querySelectorAll('script');
  
  scripts.forEach((script, index) => {
    const content = String(script.textContent || '');
    if (!content) return;
    dangerousProperties.forEach((prop) => {
      const at = content.indexOf(prop);
      if (at === -1) return;
      issues.push({
        title: 'Potential DOM XSS Sink',
        description: `Script ${index + 1} uses potentially dangerous "${prop}" which may lead to DOM XSS.`,
        recommendation: 'Prefer textContent. If HTML is required, sanitize with a vetted sanitizer (e.g., DOMPurify) and apply a strict CSP.',
        severity: 'high',
        highlight: prop,
        evidence: extractEvidenceLine(content, at) ? `Inline script: ${extractEvidenceLine(content, at)}` : undefined,
        element: script
      });
    });
  });

  // Detect eval() only in executable JavaScript contexts.
  // Avoid scanning document.body.innerHTML which causes false positives from visible text/code samples.
  // Detect eval() only in executable JavaScript contexts.
  // Avoid false positives from visible text/code samples.
  const snippets = getExecutableJsSnippets();
  // Not preceded by dot or identifier char (best-effort to avoid matching `.eval(` or `re-eval(` style words)
  const evalRe = /(^|[^.$\w])eval\s*\(/g;
  for (const snip of snippets) {
    const original = String(snip.code || '');
    if (!original.trim()) continue;
    const normalized = stripJsStringsAndComments(original);

    let m;
    while ((m = evalRe.exec(normalized)) !== null) {
      const matchIndex = (typeof m.index === 'number') ? (m.index + String(m[1] || '').length) : 0;
      issues.push({
        title: 'Use of eval() Detected',
        description: 'eval() call detected in executable JavaScript. This can execute arbitrary code and is a common XSS primitive.',
        recommendation: 'Avoid eval(). Prefer JSON.parse(), structured data, or explicit function maps. If unavoidable, strictly validate inputs.',
        severity: 'high',
        highlight: 'eval',
        evidence: extractEvidenceLine(original, matchIndex) ? `Code: ${extractEvidenceLine(original, matchIndex)}` : undefined,
        element: snip.el
      });
    }
  }

  return issues;
}

// ==================== CSRF CHECKS ====================
function checkCSRF() {
  const issues = [];
  
  // Check forms without CSRF tokens (already checked in form security)
  // Check for state-changing GET requests
  const links = Array.from(document.querySelectorAll('a[href*="delete"], a[href*="remove"], a[href*="edit"], a[href*="update"]'));
  for (const a of links) {
    const href = a.getAttribute('href') || '';
    issues.push({
      title: 'Potential State-Changing GET Request',
      description: `Link may trigger a state change via GET: ${href.slice(0, 180)}`,
      recommendation: 'Use POST requests with CSRF tokens for all state-changing operations.',
      severity: 'high',
      highlight: 'href',
      element: a
    });
  }

  // Check for AJAX requests without CSRF protection
  const inlineScripts = Array.from(document.querySelectorAll('script'))
    .filter(s => !s.src)
    .map(s => ({ el: s, text: String(s.textContent || '') }));
  const combined = inlineScripts.map(s => s.text).join(' ');
  const usesAjax = combined.includes('XMLHttpRequest') || combined.includes('fetch(');
  const mentionsToken = /csrf|token/i.test(combined);
  if (usesAjax && !mentionsToken) {
    const first = inlineScripts.find(s => s.text.includes('fetch(') || s.text.includes('XMLHttpRequest')) || null;
    issues.push({
      title: 'AJAX Requests May Lack CSRF Protection',
      description: 'Page uses AJAX (fetch/XMLHttpRequest) but no CSRF token usage was detected in inline scripts.',
      recommendation: 'Include CSRF tokens in all AJAX request headers or bodies (and validate server-side).',
      severity: 'high',
      highlight: first && first.text.includes('fetch(') ? 'fetch(' : 'XMLHttpRequest',
      evidence: first ? `Inline script: ${String(first.text).trim().split('\n').find(l => l.includes('fetch(') || l.includes('XMLHttpRequest')) || String(first.text).trim().slice(0, 240)}` : undefined,
      element: first ? first.el : undefined
    });
  }

  return issues;
}

// ==================== INPUT VALIDATION CHECKS ====================
function checkInputValidation() {
  const issues = [];
  const inputs = document.querySelectorAll('input, textarea');

  inputs.forEach((input, index) => {
    const tag = (input.tagName || '').toLowerCase();
    const type = tag === 'textarea' ? 'textarea' : ((input.getAttribute('type') || 'text').toLowerCase());
    const pattern = input.getAttribute('pattern');
    const maxlength = input.getAttribute('maxlength');
    const minlength = input.getAttribute('minlength');
    const name = input.getAttribute('name') || `input-${index}`;

    // Check for missing length bounds
    if (type === 'text' || type === 'search') {
      if (!maxlength) {
        issues.push({
          title: `No Max Length on ${name}`,
          description: `Input field "${name}" has no maximum length constraint.`,
          recommendation: 'Set maxlength attribute to prevent buffer overflow and DoS attacks.',
          severity: 'low',
          element: input
        });
      }
    }

    // Textareas: pattern isn’t a reliable control; prefer maxlength + server-side validation.
    if (type === 'textarea') {
      if (!maxlength) {
        issues.push({
          title: `No Max Length on ${name}`,
          description: `Textarea "${name}" has no maximum length constraint.`,
          recommendation: 'Set maxlength to reduce abuse/DoS risk; validate server-side.',
          severity: 'low',
          element: input
        });
      }
    }

    // Check email inputs
    if (type === 'email' && !pattern) {
      issues.push({
        title: `Basic Email Validation on ${name}`,
        description: `Email field "${name}" relies only on browser validation.`,
        recommendation: 'Add server-side email validation and consider pattern attribute for client-side.',
        severity: 'low',
        element: input
      });
    }

    // Check URL inputs
    if (type === 'url') {
      issues.push({
        title: `URL Input Detected: ${name}`,
        description: `URL input "${name}" detected. Ensure proper validation against SSRF and open redirect.`,
        recommendation: 'Validate URL scheme, domain whitelist, and prevent internal network access.',
        severity: 'medium',
        element: input
      });
    }

    // Check for missing input sanitization hints (inputs only)
    if (type === 'text' || type === 'search') {
      if (!input.hasAttribute('pattern') && !input.hasAttribute('inputmode')) {
        issues.push({
          title: `Generic Text Input: ${name}`,
          description: `Text input "${name}" has no validation pattern or input mode.`,
          recommendation: 'Add pattern attribute for expected input format and validate server-side.',
          severity: 'low',
          element: input
        });
      }
    }
  });

  return issues;
}

// ==================== AUTHENTICATION CHECKS ====================
function checkAuthentication() {
  const issues = [];

  // Check for password fields
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  passwordFields.forEach((field, index) => {
    const form = field.closest('form');
    
    // Check for password field without proper label
    const label = document.querySelector(`label[for="${field.id}"]`);
    if (!label && !field.getAttribute('aria-label')) {
      issues.push({
        title: `Password Field ${index + 1} Missing Label`,
        description: 'Password field lacks proper labeling for accessibility.',
        recommendation: 'Add proper label or aria-label for accessibility and screen readers.',
        severity: 'low',
        highlight: 'type',
        element: field
      });
    }

    // Check for "show password" functionality
    const showPasswordToggle = form ? form.querySelector('[type="checkbox"][id*="show"], [type="checkbox"][id*="toggle"]') : null;
    if (!showPasswordToggle) {
      issues.push({
        title: 'No Password Visibility Toggle',
        description: 'Password field does not have a show/hide password option.',
        recommendation: 'Add password visibility toggle to improve user experience.',
        severity: 'low',
        element: field
      });
    }

    // Check for autocomplete
    const autocomplete = field.getAttribute('autocomplete');
    if (autocomplete === 'on' || !autocomplete) {
      issues.push({
        title: 'Password Field Autocomplete Enabled',
        description: `Password field ${index + 1} has autocomplete enabled or not set.`,
        recommendation: 'Use autocomplete="current-password" or "new-password" appropriately.',
        severity: 'low',
        highlight: 'autocomplete',
        element: field
      });
    }
  });

  // Check for username fields
  const usernameFields = document.querySelectorAll('input[name*="user"], input[name*="email"], input[name*="login"]');
  usernameFields.forEach((field, index) => {
    const autocomplete = field.getAttribute('autocomplete');
    if (!autocomplete || autocomplete === 'on') {
      issues.push({
        title: 'Username Field Autocomplete',
        description: `Username field has generic autocomplete setting.`,
        recommendation: 'Use autocomplete="username" or "email" for better browser handling.',
        severity: 'low',
        highlight: 'autocomplete',
        element: field
      });
    }
  });

  // Check for remember me checkbox
  const rememberMe = document.querySelector('input[type="checkbox"][name*="remember"]');
  if (rememberMe) {
    issues.push({
      title: '"Remember Me" Functionality Detected',
      description: 'Remember me checkbox found. Ensure tokens are securely stored.',
      recommendation: 'Use secure, HttpOnly cookies with appropriate expiration times for persistent sessions.',
      severity: 'medium',
      highlight: 'remember',
      element: rememberMe
    });
  }

  // Check for OAuth/Social login buttons
  const socialButtons = document.querySelectorAll('[href*="oauth"], [href*="facebook"], [href*="google"], [href*="github"]');
  if (socialButtons.length > 0) {
    issues.push({
      title: 'Third-Party Authentication Detected',
      description: 'OAuth or social login buttons detected.',
      recommendation: 'Ensure proper OAuth 2.0 implementation with state parameter for CSRF protection.',
      severity: 'medium',
      highlight: 'oauth',
      element: socialButtons[0]
    });
  }

  return issues;
}

// ==================== SESSION MANAGEMENT CHECKS ====================
function checkSessionManagement() {
  const issues = [];

  // Check for session cookies (comprehensive list of session/auth/security cookie keywords)
  const cookies = document.cookie.split(';');
  const sessionKeywords = [
    'session', 'sess', 'sid', 'auth', 'token', 'jwt', 'bearer', 'identity', 'login',
    'csrf', 'xsrf', 'remember', 'oauth', 'openid', 'phpsessid', 'jsessionid',
    'connect.sid', 'django', 'flask', 'rails', 'aspnet', 'adonis', 'nest_session',
    'cfid', 'cftoken', 'hsid', 'ssid', 'sapisid'
  ];
  const sessionCookies = cookies.filter(c => {
    const lower = c.toLowerCase();
    return sessionKeywords.some(k => lower.includes(k))
      || lower.startsWith('__secure-') || lower.startsWith('__host-')
      || lower.startsWith('_shopify_') || lower.startsWith('wp-settings');
  });

  if (sessionCookies.length > 0) {
    issues.push({
      title: 'Session Cookies Detected',
      description: `Found ${sessionCookies.length} potential session cookie(s).`,
      recommendation: 'Ensure session cookies use Secure, HttpOnly, SameSite=Strict flags and rotate on privilege changes.',
      severity: 'medium'
    });
  }

  // Check for session ID in URL
  if (window.location.href.match(/sessionid|session_id|sess|token=/i)) {
    issues.push({
      title: 'Session ID in URL',
      description: 'Session identifier detected in URL. This is a critical security flaw.',
      recommendation: 'Never pass session identifiers in URLs. Use cookies with proper flags.',
      severity: 'critical'
    });
  }

  // Check for logout functionality
  const logoutLinks = document.querySelectorAll('a[href*="logout"], a[href*="signout"], button[id*="logout"]');
  if (logoutLinks.length === 0 && sessionCookies.length > 0) {
    issues.push({
      title: 'No Visible Logout Mechanism',
      description: 'Session appears active but no logout link/button found.',
      recommendation: 'Provide clear logout functionality that invalidates sessions server-side.',
      severity: 'medium'
    });
  }

  // Concurrent session monitoring is primarily server-side and cannot be reliably detected from a content script.
  // To avoid false positives, only flag when we have strong signals the page is doing auth/session management.
  if (sessionCookies.length > 0) {
    const scripts = Array.from(document.querySelectorAll('script'))
      .filter(s => !s.src)
      .map(s => s.textContent)
      .join(' ');
    if (!scripts.includes('concurrent') && !scripts.includes('duplicate')) {
      issues.push({
        title: 'Concurrent Session Controls Not Evident',
        description: 'Session cookies detected, but concurrent-session controls are not observable client-side.',
        recommendation: 'Ensure server-side controls exist (session invalidation, rotation, device/session listings).',
        severity: 'low'
      });
    }
  }

  return issues;
}

// ==================== CRYPTOGRAPHY CHECKS ====================
function checkCryptography() {
  const issues = [];

  // Check if page is served over HTTPS
  if (window.location.protocol === 'http:') {
    issues.push({
      title: 'Page Served Over HTTP',
      description: 'This page is served over insecure HTTP protocol.',
      recommendation: 'Use HTTPS for all pages, especially those handling sensitive data.',
      severity: 'critical'
    });
  }

  // Check for weak crypto usage in inline scripts (best-effort).
  const scriptEls = Array.from(document.querySelectorAll('script'));
  const inlineScripts = scriptEls
    .filter(s => !s.src)
    .map(s => ({ el: s, text: String(s.textContent || '') }));

  function maskJsCommentsAndStrings(input) {
    // Returns a same-length string where characters inside strings/comments are replaced with spaces.
    // This keeps indices aligned so we can map matches back to the original source.
    const s = String(input || '');
    const out = s.split('');

    const MODE = {
      CODE: 0,
      SQUOTE: 1,
      DQUOTE: 2,
      TEMPLATE: 3,
      LINE_COMMENT: 4,
      BLOCK_COMMENT: 5
    };

    let mode = MODE.CODE;
    let i = 0;

    // For template literals: allow ${ ... } expressions to be treated as code.
    const stack = [];
    let templateExprDepth = 0;

    function maskChar(idx) {
      if (idx >= 0 && idx < out.length && out[idx] !== '\n') out[idx] = ' ';
    }

    while (i < s.length) {
      const ch = s[i];
      const next = i + 1 < s.length ? s[i + 1] : '';

      if (mode === MODE.LINE_COMMENT) {
        maskChar(i);
        if (ch === '\n') mode = MODE.CODE;
        i++;
        continue;
      }

      if (mode === MODE.BLOCK_COMMENT) {
        maskChar(i);
        if (ch === '*' && next === '/') {
          maskChar(i + 1);
          i += 2;
          mode = MODE.CODE;
          continue;
        }
        i++;
        continue;
      }

      if (mode === MODE.SQUOTE) {
        maskChar(i);
        if (ch === '\\') {
          // escape next char
          if (i + 1 < s.length) maskChar(i + 1);
          i += 2;
          continue;
        }
        if (ch === "'") {
          mode = MODE.CODE;
        }
        i++;
        continue;
      }

      if (mode === MODE.DQUOTE) {
        maskChar(i);
        if (ch === '\\') {
          if (i + 1 < s.length) maskChar(i + 1);
          i += 2;
          continue;
        }
        if (ch === '"') {
          mode = MODE.CODE;
        }
        i++;
        continue;
      }

      if (mode === MODE.TEMPLATE) {
        // Inside template literal text.
        maskChar(i);
        if (ch === '\\') {
          if (i + 1 < s.length) maskChar(i + 1);
          i += 2;
          continue;
        }

        // Enter ${ expression }
        if (ch === '$' && next === '{') {
          // Unmask ${ so code inside can be analyzed.
          out[i] = '$';
          out[i + 1] = '{';
          i += 2;
          stack.push(MODE.TEMPLATE);
          mode = MODE.CODE;
          templateExprDepth = 1;
          continue;
        }

        if (ch === '`') {
          mode = MODE.CODE;
        }
        i++;
        continue;
      }

      // CODE mode
      if (ch === '/' && next === '/') {
        // Start line comment
        maskChar(i);
        maskChar(i + 1);
        i += 2;
        mode = MODE.LINE_COMMENT;
        continue;
      }
      if (ch === '/' && next === '*') {
        // Start block comment
        maskChar(i);
        maskChar(i + 1);
        i += 2;
        mode = MODE.BLOCK_COMMENT;
        continue;
      }
      if (ch === "'") {
        maskChar(i);
        mode = MODE.SQUOTE;
        i++;
        continue;
      }
      if (ch === '"') {
        maskChar(i);
        mode = MODE.DQUOTE;
        i++;
        continue;
      }
      if (ch === '`') {
        maskChar(i);
        mode = MODE.TEMPLATE;
        i++;
        continue;
      }

      // If we're temporarily in a template expression, track braces to return to TEMPLATE mode.
      if (templateExprDepth > 0) {
        if (ch === '{') templateExprDepth++;
        else if (ch === '}') templateExprDepth--;

        if (templateExprDepth === 0) {
          // Return to TEMPLATE mode (continue masking template text).
          mode = stack.pop() || MODE.CODE;
        }
      }

      i++;
    }

    return out.join('');
  }

  const allInlineText = inlineScripts.map(s => s.text).join('\n');
  const allInlineMasked = maskJsCommentsAndStrings(allInlineText);

  const weakDetectors = [
    {
      name: 'MD5',
      message: 'MD5 hash detected. MD5 is cryptographically broken.',
      re: /\b(?:CryptoJS\.)?MD5\b|\bmd5\w*\s*\(/i
    },
    {
      name: 'SHA1',
      message: 'SHA-1 detected. SHA-1 is deprecated and should not be used.',
      re: /\b(?:CryptoJS\.)?SHA1\b|\bsha1\s*\(/i
    },
    {
      name: 'DES',
      message: 'DES encryption detected. DES is obsolete and insecure.',
      re: /\b(?:CryptoJS\.)?DES\b|\bdes\s*\(/i
    },
    {
      name: 'RC4',
      message: 'RC4 cipher detected. RC4 is broken and should not be used.',
      re: /\bRC4\b|\brc4\s*\(/i
    }
  ];

  function extractEvidenceLine(text, matchIndex) {
    const idx = Math.max(0, Math.min(text.length, Number(matchIndex) || 0));
    const start = text.lastIndexOf('\n', idx - 1) + 1;
    const endRaw = text.indexOf('\n', idx);
    const end = endRaw === -1 ? text.length : endRaw;
    const line = text.slice(start, end);
    return line.trim().slice(0, 240);
  }

  for (const det of weakDetectors) {
    let found = null;

    for (const s of inlineScripts) {
      const masked = maskJsCommentsAndStrings(s.text);
      const m = masked.match(det.re);
      if (!m) continue;
      const matchTextRaw = String(m[0] || det.name);
      const matchText = matchTextRaw.replace(/\($/, '');
      const at = typeof m.index === 'number' ? m.index : s.text.indexOf(matchText);

      found = {
        el: s.el,
        matchText,
        evidenceLine: extractEvidenceLine(s.text, at)
      };
      break;
    }

    // Back-compat fallback: if regex didn't match but the plain token exists anywhere, still flag it.
    if (!found && allInlineMasked.includes(det.name)) {
      for (const s of inlineScripts) {
        const masked = maskJsCommentsAndStrings(s.text);
        const at = masked.indexOf(det.name);
        if (at === -1) continue;
        found = {
          el: s.el,
          matchText: det.name,
          evidenceLine: extractEvidenceLine(s.text, at)
        };
        break;
      }
    }

    if (found) {
      issues.push({
        title: `Weak Cryptography: ${det.name}`,
        description: det.message,
        evidence: found.evidenceLine ? `Inline script: ${found.evidenceLine}` : undefined,
        highlight: found.matchText,
        recommendation: 'Use modern algorithms: SHA-256 or higher for hashing, AES-256 for encryption.',
        severity: 'high',
        element: found.el
      });
    }
  }

  // Check for crypto libraries
  if (allInlineMasked.includes('CryptoJS') || allInlineMasked.includes('forge') || allInlineMasked.includes('crypto-js')) {
    issues.push({
      title: 'Client-Side Cryptography Detected',
      description: 'Cryptographic operations appear to be performed client-side.',
      recommendation: 'Prefer server-side cryptography. If client-side is necessary, use Web Crypto API.',
      severity: 'medium'
    });
  }

  // Check for localStorage with sensitive data
  if (allInlineMasked.includes('localStorage.setItem') || allInlineMasked.includes('sessionStorage.setItem')) {
    issues.push({
      title: 'Browser Storage Usage Detected',
      description: 'Data is being stored in localStorage or sessionStorage.',
      recommendation: 'Do not store sensitive data in browser storage. Encrypt if necessary.',
      severity: 'medium'
    });
  }

  return issues;
}

// ==================== ACCESS CONTROL CHECKS ====================
function checkAccessControl() {
  const issues = [];

  function isLikelyAdminOrDebugText(text) {
    const t = String(text || '').toLowerCase();
    if (!t) return false;
    // Strong signals
    if (t.includes('admin') || t.includes('debug')) return true;

    // "test" is too generic (e.g., "Test new features").
    // Only treat it as a signal when it looks like an environment / internal feature toggle context.
    const hasTestWord = /\btest(ing)?\b/i.test(t);
    if (!hasTestWord) return false;
    if (/\b(staging|sandbox|internal|qa|dev|preprod|beta)\b/i.test(t)) return true;
    if (/\b(feature flag|featureflag|experiments?|ab test|rollout|canary)\b/i.test(t)) return true;
    return false;
  }

  // Check for admin/restricted areas
  if (window.location.href.match(/\/admin|\/dashboard|\/panel|\/manage/i)) {
    issues.push({
      title: 'Administrative Area Detected',
      description: 'This appears to be an administrative or restricted area.',
      recommendation: 'Ensure proper authentication, authorization, and audit logging for admin areas.',
      severity: 'high'
    });
  }

  // Check for hidden admin links
  const hiddenElements = document.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"]');
  hiddenElements.forEach((element) => {
    const text = String(element.textContent || '');
    const href = element.getAttribute && element.getAttribute('href') ? String(element.getAttribute('href')) : '';
    const hrefIsSuspicious = /\b(staging|sandbox|internal|qa|dev|preprod|admin|debug)\b/i.test(href) || /\/(?:admin|debug|test|qa|staging|sandbox)(?:\/|\b)/i.test(href);

    if (isLikelyAdminOrDebugText(text) || hrefIsSuspicious) {
      const lower = String(text).toLowerCase();
      issues.push({
        title: 'Hidden Administrative Content',
        description: 'Hidden elements contain administrative or debug content.',
        recommendation: 'Remove debug/admin content from production. Implement proper access controls.',
        severity: 'high',
        highlight: lower.includes('admin') ? 'admin' : lower.includes('debug') ? 'debug' : (hrefIsSuspicious ? 'href' : 'test'),
        element
      });
    }
  });

  // Check for CORS
  const scripts = Array.from(document.querySelectorAll('script')).map(s => s.textContent).join(' ');
  if (scripts.includes('Access-Control-Allow-Origin') || scripts.includes('cors')) {
    issues.push({
      title: 'CORS Implementation Detected',
      description: 'Cross-Origin Resource Sharing appears to be configured.',
      recommendation: 'Ensure CORS is not set to "*" and properly validates origins. Use credentials carefully.',
      severity: 'medium'
    });
  }

  // Check for file listings
  const anchors = Array.from(document.querySelectorAll('a'));
  const suspicious = anchors.find((a) => {
    const txt = String(a.textContent || '').toLowerCase();
    const href = String(a.getAttribute('href') || '').toLowerCase();
    return txt.includes('parent directory') || txt.includes('../') || href.includes('../');
  }) || null;
  if (suspicious) {
    issues.push({
      title: 'Directory Listing Detected',
      description: 'Directory listing appears to be enabled (e.g., "Parent Directory" link found).',
      recommendation: 'Disable directory listing on the web server. This exposes file structure and often sensitive files.',
      severity: 'high',
      highlight: 'Parent Directory',
      element: suspicious
    });
  }

  return issues;
}

// ==================== API ENDPOINT CHECKS ====================
function checkAPIEndpoints() {
  const issues = [];

  function extractEvidenceLine(text, matchIndex) {
    const idx = Math.max(0, Math.min(String(text || '').length, Number(matchIndex) || 0));
    const s = String(text || '');
    const start = s.lastIndexOf('\n', idx - 1) + 1;
    const endRaw = s.indexOf('\n', idx);
    const end = endRaw === -1 ? s.length : endRaw;
    return s.slice(start, end).trim().slice(0, 300);
  }

  function redactToken(value) {
    const v = String(value || '');
    if (v.length <= 10) return v;
    return `${v.slice(0, 4)}…${v.slice(-4)}`;
  }

  function redactSecretsInLine(line, rawToken) {
    const l = String(line || '');
    const t = String(rawToken || '');
    if (!t) return l;
    return l.split(t).join(redactToken(t));
  }

  const scriptEls = Array.from(document.querySelectorAll('script'))
    .filter((s) => {
      const typeAttr = (s.getAttribute('type') || '').toLowerCase();
      const isJsType = typeAttr === '' || typeAttr === 'text/javascript' || typeAttr === 'application/javascript' || typeAttr === 'module';
      return isJsType;
    });

  const seenApiKeyFindings = new Set();
  
  // Check for API keys
  // Capture the *name* as well as the value so we can show only the important part.
  // Example matches: secretKey:"...", access_token="..."
  const apiKeyPatterns = [
    /(api[_-]?key)["\s:=]+["']([a-zA-Z0-9_-]{20,})["']/gi,
    /(apikey)["\s:=]+["']([a-zA-Z0-9_-]{20,})["']/gi,
    /(access[_-]?token)["\s:=]+["']([a-zA-Z0-9_-]{20,})["']/gi,
    /(secret[_-]?key)["\s:=]+["']([a-zA-Z0-9_-]{20,})["']/gi
  ];

  for (let scriptIdx = 0; scriptIdx < scriptEls.length; scriptIdx++) {
    const script = scriptEls[scriptIdx];
    if (script.src) continue; // cannot read cross-origin external script content reliably
    const code = String(script.textContent || '');
    if (!code.trim()) continue;

    for (const pattern of apiKeyPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(code)) !== null) {
        const keyName = m[1] ? String(m[1]) : 'token';
        const token = m[2] ? String(m[2]) : '';
        const idx = typeof m.index === 'number' ? m.index : 0;
        const evidenceLine = extractEvidenceLine(code, idx);

        const dedupeKey = `${scriptIdx}|${keyName.toLowerCase()}|${token}`;
        if (seenApiKeyFindings.has(dedupeKey)) continue;
        seenApiKeyFindings.add(dedupeKey);

        issues.push({
          title: `API Key Exposed in Client Code: ${keyName}`,
          description: 'API key or access token appears in client-side JavaScript (high risk of leakage).',
          recommendation: 'Remove secrets from client bundles. Use a server-side proxy or short-lived tokens tied to an authenticated user.',
          severity: 'critical',
          highlight: keyName,
          evidence: `Key: ${keyName} = ${redactToken(token)}${evidenceLine ? `\nCode: ${redactSecretsInLine(evidenceLine, token)}` : ''}`,
          element: script
        });
      }
    }
  }

  // Check for API endpoints
  const apiEndpointPattern = /["'](https?:\/\/[^"']*\/api[^"']*)["']/gi;

  for (const script of scriptEls) {
    if (script.src) continue;
    const code = String(script.textContent || '');
    if (!code.trim()) continue;

    apiEndpointPattern.lastIndex = 0;
    let m;
    while ((m = apiEndpointPattern.exec(code)) !== null) {
      const url = m[1] ? String(m[1]) : '';
      const idx = typeof m.index === 'number' ? m.index : 0;
      const evidenceLine = extractEvidenceLine(code, idx);
      issues.push({
        title: 'API Endpoint Exposed in Client Code',
        description: `API endpoint referenced in client-side JavaScript: ${url}`,
        recommendation: 'Ensure endpoints require authentication/authorization and enforce rate limiting and input validation server-side.',
        severity: 'medium',
        highlight: '/api',
        evidence: evidenceLine ? `Code: ${evidenceLine}` : undefined,
        element: script
      });
    }
  }

  // Check for GraphQL endpoints
  const graphqlRe = /(https?:\/\/[^\s"']*\/graphql\b|\/graphql\b|\bgraphql\b)/gi;
  for (const script of scriptEls) {
    if (script.src) continue;
    const code = String(script.textContent || '');
    if (!code.trim()) continue;

    graphqlRe.lastIndex = 0;
    let m;
    while ((m = graphqlRe.exec(code)) !== null) {
      const idx = typeof m.index === 'number' ? m.index : 0;
      const evidenceLine = extractEvidenceLine(code, idx);
      issues.push({
        title: 'GraphQL Endpoint Detected',
        description: 'GraphQL usage detected in client-side code.',
        recommendation: 'Disable introspection in production (where feasible), enforce authZ on every resolver, and add depth/complexity limits + rate limiting.',
        severity: 'medium',
        highlight: 'graphql',
        evidence: evidenceLine ? `Code: ${evidenceLine}` : undefined,
        element: script
      });
    }
  }

  // Check for webhook URLs
  // Reduce false positives: only flag when it looks like an actual URL/path reference.
  const webhookUrlRe = /["'](https?:\/\/[^"']*(?:webhook|callback|notify)[^"']*|\/(?:webhook|callback|notify)\b[^"']*)["']/gi;
  for (const script of scriptEls) {
    if (script.src) continue;
    const code = String(script.textContent || '');
    if (!code.trim()) continue;

    webhookUrlRe.lastIndex = 0;
    let m;
    while ((m = webhookUrlRe.exec(code)) !== null) {
      const url = m[1] ? String(m[1]) : '';
      const idx = typeof m.index === 'number' ? m.index : 0;
      const evidenceLine = extractEvidenceLine(code, idx);
      issues.push({
        title: 'Webhook/Callback URL Referenced in Client Code',
        description: `Potential webhook/callback URL referenced in client-side code: ${url}`,
        recommendation: 'If this is a real webhook/callback, ensure HTTPS, validate signatures, enforce allowlists, and protect against replay attacks.',
        severity: 'medium',
        highlight: 'callback',
        evidence: evidenceLine ? `Code: ${evidenceLine}` : undefined,
        element: script
      });
    }
  }

  return issues;
}

// ==================== THIRD PARTY SCRIPTS CHECKS ====================
function checkThirdPartyScripts() {
  const issues = [];
  const scripts = document.querySelectorAll('script[src]');
  
  const externalScripts = Array.from(scripts).filter(script => {
    const src = script.getAttribute('src');
    return src && !src.startsWith('/') && !src.startsWith(window.location.origin);
  });

  if (externalScripts.length > 0) {
    issues.push({
      title: 'Third-Party Scripts Loaded',
      description: `Found ${externalScripts.length} third-party script(s). Each is a potential security risk.`,
      recommendation: 'Use Subresource Integrity (SRI) for all third-party scripts. Review scripts regularly.',
      severity: 'medium'
    });

    // Check for SRI
    externalScripts.forEach((script, index) => {
      if (!script.hasAttribute('integrity')) {
        const src = script.getAttribute('src');
        const host = (() => {
          try { return new URL(src, window.location.href).hostname; } catch { return String(src || ''); }
        })();
        issues.push({
          title: `Third-Party Script Without SRI`,
          description: `Third-party script from "${host}" lacks integrity attribute.`,
          recommendation: 'Add integrity and crossorigin attributes to prevent tampering.',
          severity: 'medium',
          highlight: 'integrity',
          evidence: src ? `src: ${String(src).slice(0, 240)}` : undefined,
          element: script
        });
      }
    });
  }

  // Check for CDN usage
  const cdnDomains = ['cdn.', 'cloudflare.', 'jsdelivr.', 'unpkg.', 'cdnjs.'];
  scripts.forEach(script => {
    const src = script.getAttribute('src') || '';
    if (cdnDomains.some(cdn => src.includes(cdn))) {
      if (!script.hasAttribute('integrity')) {
        issues.push({
          title: 'CDN Script Without Integrity Check',
          description: 'Script loaded from CDN without SRI integrity check.',
          recommendation: 'Always use SRI when loading scripts from CDNs.',
          severity: 'high',
          highlight: 'integrity',
          evidence: src ? `src: ${String(src).slice(0, 240)}` : undefined,
          element: script
        });
      }
    }
  });

  // Check for analytics/tracking
  const trackingDomains = ['google-analytics', 'googletagmanager', 'facebook.net', 'doubleclick'];
  scripts.forEach(script => {
    const src = script.getAttribute('src') || '';
    if (trackingDomains.some(domain => src.includes(domain))) {
      issues.push({
        title: 'Tracking/Analytics Script Detected',
        description: 'Third-party tracking script found. May collect user data.',
        recommendation: 'Ensure privacy policy covers third-party tracking. Consider first-party analytics.',
        severity: 'low',
        highlight: 'src',
        evidence: src ? `src: ${String(src).slice(0, 240)}` : undefined,
        element: script
      });
    }
  });

  return issues;
}

// ==================== DATA EXPOSURE CHECKS ====================
function checkDataExposure() {
  const issues = [];

  // Check for exposed sensitive data in visible page text
  const sensitivePatterns = {
    'email': /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    'phone': /(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}/g,
    'ssn': /\d{3}-\d{2}-\d{4}/g,
    'credit card': /\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/g,
    'ip address': /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
  };

  function redactPhone(value) {
    const s = String(value || '');
    const digits = s.replace(/\D/g, '');
    if (digits.length < 4) return s;
    const last4 = digits.slice(-4);
    return `…${last4}`;
  }

  function isInExcludedContainer(el) {
    try {
      return !!(el && el.closest && el.closest('script,style,noscript,template,head'));
    } catch {
      return false;
    }
  }

  function isLikelyVisibleElement(el) {
    try {
      if (!el || !el.tagName) return false;
      if (isInExcludedContainer(el)) return false;
      if (el.hidden) return false;
      if (el.getAttribute && el.getAttribute('aria-hidden') === 'true') return false;
      const style = window.getComputedStyle ? window.getComputedStyle(el) : null;
      if (style) {
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
      }
      if (el.getClientRects && el.getClientRects().length === 0) return false;
      return true;
    } catch {
      return true;
    }
  }

  function isPlausiblePhoneMatch(rawMatch, surrounding) {
    const match = String(rawMatch || '');
    const digits = match.replace(/\D/g, '');
    if (digits.length < 10 || digits.length > 15) return false;

    // If formatted (contains separators/plus/paren), it's more likely a real phone.
    if (/[+().\-\s]/.test(match)) return true;

    // Otherwise require nearby phone keywords to reduce ID/version false positives.
    const ctx = String(surrounding || '');
    return /(tel|phone|call|mobile|cell|contact|whatsapp)/i.test(ctx);
  }

  function collectMatchesFromVisibleText(type, pattern, maxMatches = 50) {
    const matches = [];
    let first = null;

    try {
      if (!document.body) return { matches, first };
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const txt = String(node.nodeValue || '');
        if (!txt || txt.length < 6) continue;
        const el = node.parentElement;
        if (!el || !isLikelyVisibleElement(el)) continue;

        pattern.lastIndex = 0;
        let m;
        while ((m = pattern.exec(txt))) {
          const val = String(m[0] || '');
          if (!val) continue;

          if (type === 'phone') {
            const start = Math.max(0, m.index - 25);
            const end = Math.min(txt.length, m.index + val.length + 25);
            const ctx = txt.slice(start, end);
            if (!isPlausiblePhoneMatch(val, ctx)) continue;
          }

          matches.push(val);
          if (!first) first = { el, match: val };
          if (matches.length >= maxMatches) return { matches, first };
        }
      }
    } catch {
      // ignore
    }

    return { matches, first };
  }

  Object.entries(sensitivePatterns).forEach(([type, pattern]) => {
    const { matches, first } = collectMatchesFromVisibleText(type, new RegExp(pattern.source, pattern.flags));
    if (!matches || matches.length === 0) return;

    // Keep proof minimal: show up to 3 examples.
    const examples = Array.from(new Set(matches)).slice(0, 3);
    const proof = (() => {
      if (type === 'phone') {
        return `Examples: ${examples.map(redactPhone).join(', ')}`;
      }
      // For other types, don't dump full values; show shortened samples.
      return `Examples: ${examples.map(v => String(v).slice(0, 6) + '…').join(', ')}`;
    })();

    issues.push({
      title: `Potential ${type.charAt(0).toUpperCase() + type.slice(1)} Exposure`,
      description: `Found ${matches.length} potential ${type} pattern(s) in page content.`,
      recommendation: `Mask or encrypt ${type}s. Only display what's necessary.`,
      severity: type === 'credit card' || type === 'ssn' ? 'critical' : 'medium',
      evidence: proof,
      highlight: (type === 'phone' && first && first.match) ? String(first.match).replace(/\D/g, '').slice(-4) : undefined,
      element: (type === 'phone' && first && first.el) ? first.el : undefined
    });
  });

  // Check for comments with sensitive info
  const comments = document.evaluate('//comment()', document, null, XPathResult.ANY_TYPE, null);
  let comment = comments.iterateNext();
  let commentCount = 0;
  
  while (comment) {
    const commentText = comment.textContent.toLowerCase();
    if (commentText.includes('password') || commentText.includes('key') || 
        commentText.includes('secret') || commentText.includes('token') ||
        commentText.includes('todo') || commentText.includes('fixme')) {
      commentCount++;
    }
    comment = comments.iterateNext();
  }

  if (commentCount > 0) {
    issues.push({
      title: 'Sensitive Information in Comments',
      description: `Found ${commentCount} HTML comment(s) containing potentially sensitive keywords.`,
      recommendation: 'Remove all sensitive comments from production code.',
      severity: 'medium'
    });
  }

  // Check for data in meta tags
  const metaTags = document.querySelectorAll('meta');
  metaTags.forEach(meta => {
    const content = meta.getAttribute('content') || '';
    if (content.length > 100) {
      issues.push({
        title: 'Large Data in Meta Tag',
        description: 'Meta tag contains large amount of data that may expose sensitive information.',
        recommendation: 'Review meta tag content. Do not store sensitive data in meta tags.',
        severity: 'low'
      });
    }
  });

  // Check for exposed object/JSON data
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join(' ');
  if (scripts.match(/var\s+\w+\s*=\s*\{[\s\S]{500,}\}/)) {
    issues.push({
      title: 'Large JavaScript Objects Detected',
      description: 'Large data objects found in inline scripts.',
      recommendation: 'Load data via API instead of embedding in HTML. Reduces page size and exposure.',
      severity: 'low'
    });
  }

  return issues;
}

// ==================== MISCELLANEOUS CHECKS ====================
function checkMiscellaneous() {
  const issues = [];

  // Check for debug mode
  const scripts = Array.from(document.querySelectorAll('script')).map(s => s.textContent).join(' ');
  if (scripts.includes('debug:true') || scripts.includes('DEBUG') || scripts.includes('console.log')) {
    issues.push({
      title: 'Debug Code in Production',
      description: 'Debug code or console.log statements found.',
      recommendation: 'Remove all debug code from production builds.',
      severity: 'low'
    });
  }

  // Check for source maps
  const sourceMaps = Array.from(document.querySelectorAll('script')).filter(s => 
    s.textContent.includes('//# sourceMappingURL')
  );
  if (sourceMaps.length > 0) {
    issues.push({
      title: 'Source Maps Enabled',
      description: 'Source maps are exposed in production.',
      recommendation: 'Disable source maps in production to prevent source code exposure.',
      severity: 'medium'
    });
  }

  // Check for error messages
  if (document.body.textContent.match(/error|exception|stack trace|warning/i)) {
    const errorElements = document.querySelectorAll('[class*="error"], [id*="error"]');
    if (errorElements.length > 0 && errorElements[0].textContent.length > 50) {
      issues.push({
        title: 'Detailed Error Messages',
        description: 'Detailed error messages visible to users.',
        recommendation: 'Show generic error messages to users. Log details server-side.',
        severity: 'medium'
      });
    }
  }

  // Check for autocomplete on forms
  const forms = Array.from(document.querySelectorAll('form:not([autocomplete="off"])'));
  forms.forEach((form, index) => {
    const ac = form.getAttribute('autocomplete');
    const action = form.getAttribute('action') || '';
    const id = form.getAttribute('id') || '';
    const name = form.getAttribute('name') || '';
    const label = id ? `#${id}` : name ? `name=${name}` : action ? `action=${action}` : `form ${index + 1}`;
    issues.push({
      title: 'Form Autocomplete Enabled',
      description: `Form has autocomplete enabled (or not set): ${label}${ac ? ` (autocomplete=${ac})` : ''}.`,
      recommendation: 'Disable autocomplete on sensitive forms using autocomplete="off" (and rely on secure server-side controls).',
      severity: 'low',
      highlight: 'autocomplete',
      evidence: action ? `action: ${String(action).slice(0, 200)}` : undefined,
      element: form
    });
  });

  // Check for iframes
  const iframes = document.querySelectorAll('iframe');
  if (iframes.length > 0) {
    issues.push({
      title: 'Iframes Detected',
      description: `Found ${iframes.length} iframe(s). Each is a potential security risk.`,
      recommendation: 'Use sandbox attribute on iframes. Validate iframe sources.',
      severity: 'medium'
    });

    iframes.forEach((iframe, index) => {
      if (!iframe.hasAttribute('sandbox')) {
        issues.push({
          title: `Iframe ${index + 1} Without Sandbox`,
          description: 'Iframe lacks sandbox attribute for security isolation.',
          recommendation: 'Add sandbox attribute with minimal permissions needed.',
          severity: 'medium'
        });
      }
    });
  }

  // Check for deprecated HTML elements
  const deprecated = document.querySelectorAll('marquee, blink, font, center');
  if (deprecated.length > 0) {
    issues.push({
      title: 'Deprecated HTML Elements',
      description: 'Deprecated HTML elements detected.',
      recommendation: 'Update to modern HTML5 elements and CSS for styling.',
      severity: 'low'
    });
  }

  // Check for Flash/Java applets
  const plugins = document.querySelectorAll('object, embed, applet');
  if (plugins.length > 0) {
    issues.push({
      title: 'Browser Plugins Required',
      description: 'Page requires Flash, Java, or other plugins.',
      recommendation: 'Remove plugin dependencies. Use modern web technologies.',
      severity: 'high'
    });
  }

  // Check robots meta tag
  const robotsMeta = document.querySelector('meta[name="robots"]');
  if (!robotsMeta) {
    issues.push({
      title: 'Missing Robots Meta Tag',
      description: 'No robots meta tag found. Search engine indexing not controlled.',
      recommendation: 'Add <meta name="robots" content="..."> to control indexing.',
      severity: 'low'
    });
  }

  // Check for viewport meta
  const viewport = document.querySelector('meta[name="viewport"]');
  if (!viewport) {
    issues.push({
      title: 'Missing Viewport Meta Tag',
      description: 'No viewport meta tag for responsive design.',
      recommendation: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">',
      severity: 'low'
    });
  }

  // Check for charset declaration
  const charset = document.querySelector('meta[charset]') || document.querySelector('meta[http-equiv="Content-Type"]');
  if (!charset) {
    issues.push({
      title: 'Missing Character Set Declaration',
      description: 'No character encoding declared. May cause encoding issues.',
      recommendation: 'Add <meta charset="UTF-8"> in document head.',
      severity: 'low'
    });
  }

  // Check for external links without rel attributes
  const externalLinks = Array.from(document.querySelectorAll('a[href^="http"]')).filter(a => {
    const url = new URL(a.href);
    return url.hostname !== window.location.hostname;
  });

  externalLinks.forEach(link => {
    if (!link.hasAttribute('rel')) {
      issues.push({
        title: 'External Link Without rel Attribute',
        description: 'External link missing rel="noopener noreferrer".',
        recommendation: 'Add rel="noopener noreferrer" to external links to prevent tabnapping.',
        severity: 'low',
        element: link
      });
    }
  });

  return issues;
}
