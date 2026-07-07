// Batch 4: checkHardcodedKey through checkKeysInGit

function checkHardcodedKey() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:secret|private|encryption|signing)[_-]?key\s*[:=]\s*['"][a-zA-Z0-9+\/=_-]{16,}['"]/i.test(scripts)) {
    issues.push({ title: 'Hardcoded Cryptographic Key', description: 'Hardcoded encryption/signing key found in client-side JavaScript.', severity: 'critical', recommendation: 'Remove hardcoded keys. Use environment variables and secrets management.' });
  }
  return issues;
}

function checkHardCodedRoles() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/role\s*===?\s*['"](?:admin|superadmin|root|moderator|manager)['"]/i.test(scripts)) {
    issues.push({ title: 'Hardcoded Role Checks', description: 'Hardcoded role names used in authorization checks in client code.', severity: 'medium', recommendation: 'Use role IDs or permission-based checks instead of hardcoded role names.' });
  }
  return issues;
}

function checkHashAgility() { return []; }

function checkHashAsEncryption() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:encrypt|protect|secure).*(?:md5|sha1|sha256)\b/i.test(scripts)) {
    issues.push({ title: 'Hashing Used as Encryption', description: 'Hash function used for encryption. Hashing is one-way and not a substitute for encryption.', severity: 'high', recommendation: 'Use proper encryption algorithms (AES-GCM) instead of hash functions for data protection.' });
  }
  return issues;
}

function checkHashCollision() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\bmd5\b|\bsha1\b/i.test(scripts) && /signature|verify|integrity|certificate/i.test(scripts)) {
    issues.push({ title: 'Collision-Prone Hash for Integrity', description: 'MD5 or SHA-1 used for integrity verification. Both are vulnerable to collision attacks.', severity: 'high', recommendation: 'Use SHA-256 or SHA-3 for integrity verification.' });
  }
  return issues;
}

function checkHashLengthExtension() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:md5|sha1|sha256|sha512)\s*\(\s*(?:secret|key)/i.test(scripts)) {
    if (!/hmac/i.test(scripts)) {
      issues.push({ title: 'Hash Length Extension Vulnerability', description: 'Hash(secret + data) pattern detected without HMAC, vulnerable to length extension attacks.', severity: 'high', recommendation: 'Use HMAC (HMAC-SHA256) instead of simple hash(secret + data).' });
    }
  }
  return issues;
}

function checkHashWithoutHMAC() {
  return checkHashLengthExtension();
}

function checkHeartbleed() { return []; }

function checkHeatmapTools() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
  if (scripts.some(s => /hotjar|mouseflow|crazy\s*egg|fullstory|clicktale|smartlook|inspectlet|logrocket/i.test(s))) {
    issues.push({ title: 'Session Recording/Heatmap Tool', description: 'Session recording or heatmap tool detected. May capture sensitive user interactions.', severity: 'medium', recommendation: 'Configure session recording to redact sensitive fields (passwords, PII, payment data).' });
  }
  return issues;
}

function checkHelmSecurity() { return []; }

function checkHiddenFieldAuth() {
  const issues = [];
  const hidden = document.querySelectorAll('input[type="hidden"]');
  for (const h of hidden) {
    const name = (h.name || '').toLowerCase();
    if (/role|admin|auth|privilege|permission|access|level/i.test(name)) {
      issues.push({ title: 'Authorization in Hidden Fields', description: `Hidden field "${h.name}" may control authorization. Hidden fields are easily modified.`, severity: 'high', recommendation: 'Never use hidden fields for authorization. Validate permissions server-side only.' });
      break;
    }
  }
  return issues;
}

function checkHiddenFieldData() {
  const issues = [];
  const hidden = document.querySelectorAll('input[type="hidden"]');
  for (const h of hidden) {
    const val = h.value || '';
    if (val.length > 50 && /[a-f0-9]{32,}|eyJ[a-zA-Z0-9]/i.test(val)) {
      issues.push({ title: 'Sensitive Data in Hidden Fields', description: 'Hidden form field contains what appears to be a token, hash, or encoded data.',severity: 'medium', recommendation: 'Minimize data in hidden fields. Validate server-side and don\'t rely on hidden field integrity.' });
      break;
    }
  }
  return issues;
}

function checkHiddenFields() {
  const issues = [];
  const hidden = document.querySelectorAll('input[type="hidden"]');
  if (hidden.length > 10) {
    const names = Array.from(hidden).slice(0, 5).map(h => h.name || '(unnamed)').join(', ');
    issues.push({ title: 'Excessive Hidden Form Fields', description: `${hidden.length} hidden fields found. May contain sensitive server-side data. Fields include: ${names}...`, severity: 'low', recommendation: 'Review hidden fields for sensitive data exposure. Use server-side session storage instead.' });
  }
  return issues;
}

function checkHomographAttack() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]'));
  for (const a of links) {
    const text = a.textContent || '';
    const href = a.href || '';
    if (/[^\x00-\x7F]/.test(text) && href.startsWith('http')) {
      // Has non-ASCII chars in link text
      issues.push({ title: 'Homograph Attack Risk', description: 'Link text contains non-ASCII characters that could be used for homograph/punycode phishing.', severity: 'low', recommendation: 'Display actual domain names for links. Warn users about punycode domains.' });
      break;
    }
  }
  return issues;
}

function checkHorizontalEscalation() { return []; }

function checkHostnameExposed() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:ip-\d+-\d+-\d+-\d+|[a-z]+-[a-f0-9]{8,}|prod-\w+-\d+|web-\d+|app-\d+)\.\w+\.\w+/i.test(body + scripts)) {
    issues.push({ title: 'Internal Hostname Exposed', description: 'Internal hostname pattern detected in page content.', severity: 'medium', recommendation: 'Remove internal hostnames from client-facing content.' });
  }
  return issues;
}

function checkHPKP() {
  // HPKP is deprecated - advisory only
  return [];
}

function checkHtaccessReadable() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /\.htaccess|\.htpasswd/i.test(l))) {
    issues.push({ title: '.htaccess/.htpasswd Readable', description: 'Apache configuration files linked on page.', severity: 'critical', recommendation: 'Block access to .htaccess and .htpasswd files from the web server.' });
  }
  return issues;
}

function checkHTML5ValidationBypass() {
  const issues = [];
  const forms = document.querySelectorAll('form[novalidate], form[formnovalidate]');
  if (forms.length > 0) {
    issues.push({ title: 'HTML5 Validation Disabled', description: 'Form(s) with novalidate attribute found, disabling built-in validation.', severity: 'low', recommendation: 'If novalidate is used for custom validation, ensure server-side validation exists.' });
  }
  return issues;
}

function checkHTMLComments() {
  const issues = [];
  const comments = [];
  const walk = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
  let n;
  while (n = walk.nextNode()) comments.push(n.textContent);
  const all = comments.join('\n');
  if (/TODO|FIXME|HACK|BUG|password|secret|key|token|internal|server|database|sql/i.test(all)) {
    issues.push({ title: 'Sensitive Info in HTML Comments', description: 'HTML comments contain potentially sensitive or debug information.', severity: 'medium', recommendation: 'Remove sensitive comments from HTML in production builds.' });
  }
  return issues;
}

function checkHTTP2Push() { return []; }

function checkHumansTxt() {
  // Advisory - can't verify from content script
  return [];
}

function checkIaCScan() { return []; }
function checkIAMKeyRotation() { return []; }
function checkIAMPrivileges() { return []; }

function checkIdleTimeout() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/session|auth|login/i.test(scripts) && !/idle.*timeout|session.*timeout|inactivity.*logout|auto.*logout/i.test(scripts)) {
    issues.push({ title: 'No Idle Session Timeout', description: 'No idle/inactivity session timeout mechanism detected in client code.', severity: 'medium', recommendation: 'Implement idle session timeout (15-30 minutes) that logs out inactive users.' });
  }
  return issues;
}

function checkIDOR() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/(?:user|account|profile|order|invoice|document|file)\/\d+/i.test(scripts + window.location.href)) {
    issues.push({ title: 'IDOR (Insecure Direct Object Reference) Risk', description: 'Sequential/predictable object IDs in URLs. Users may access other users\' resources.', severity: 'high', recommendation: 'Use UUIDs instead of sequential IDs. Verify object ownership server-side.' });
  }
  return issues;
}

function checkIDTokenSignature() { return []; }
function checkIgnoredUpdatePRs() { return []; }
function checkImageSigning() { return []; }

function checkImageSSRF() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:img|image).*(?:url|src)\s*[:=].*(?:input|user|param|query|location)/i.test(scripts)) {
    issues.push({ title: 'Image URL SSRF Risk', description: 'Image source set from user-controlled input, enabling potential SSRF.', severity: 'high', recommendation: 'Validate and sanitize image URLs. Use an image proxy with domain allowlist.' });
  }
  return issues;
}

function checkIncidentResponsePlan() { return []; }

function checkInconsistentAuth() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const hasBearer = /Bearer/i.test(scripts);
  const hasCookie = /withCredentials|credentials.*include/i.test(scripts);
  const hasApiKey = /x-api-key|apikey/i.test(scripts);
  const methods = [hasBearer, hasCookie, hasApiKey].filter(Boolean).length;
  if (methods > 1) {
    issues.push({ title: 'Inconsistent Authentication Methods', description: 'Multiple authentication methods (Bearer, cookies, API keys) used simultaneously.', severity: 'medium', recommendation: 'Standardize on one authentication method per API to reduce attack surface.' });
  }
  return issues;
}

function checkIndexedDBSecurity() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/indexedDB|openDatabase/i.test(scripts)) {
    if (/token|password|secret|key|auth|session|credential/i.test(scripts)) {
      issues.push({ title: 'Sensitive Data in IndexedDB', description: 'IndexedDB stores potentially sensitive data (tokens, passwords, credentials).', severity: 'high', recommendation: 'Encrypt sensitive data before storing in IndexedDB. Consider alternatives like httpOnly cookies.' });
    }
  }
  return issues;
}

function checkInlineEventHandlers() {
  const issues = [];
  const handlers = document.querySelectorAll('[onclick], [onmouseover], [onload], [onerror], [onfocus], [onblur], [onsubmit], [onchange], [onkeyup], [onkeydown]');
  if (handlers.length > 5) {
    issues.push({ title: 'Inline Event Handlers', description: `${handlers.length} inline event handlers found. These bypass CSP and can be XSS vectors.`, severity: 'medium', recommendation: 'Use addEventListener() instead of inline event handlers. This enables strict CSP.' });
  }
  return issues;
}

function checkInnerHTML() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const count = (scripts.match(/\.innerHTML\s*[=+]/g) || []).length;
  if (count > 0) {
    issues.push({ title: 'innerHTML Assignment Detected', description: `${count} innerHTML assignment(s) found. Each is a potential XSS sink.`, severity: 'medium', recommendation: 'Use textContent or createElement instead of innerHTML. Sanitize with DOMPurify if HTML is needed.' });
  }
  return issues;
}

function checkInputLength() {
  const issues = [];
  const inputs = document.querySelectorAll('input[type="text"]:not([maxlength]), input[type="search"]:not([maxlength]), textarea:not([maxlength])');
  if (inputs.length > 3) {
    issues.push({ title: 'Input Fields Without Length Limits', description: `${inputs.length} text input(s) without maxlength attribute.`, severity: 'low', recommendation: 'Set maxlength on all text inputs. Enforce length limits server-side.' });
  }
  return issues;
}

function checkInputReflectedInError() {
  const issues = [];
  const params = new URLSearchParams(window.location.search);
  const body = document.body ? document.body.innerHTML : '';
  for (const [key, value] of params) {
    if (value.length > 5 && body.includes(value)) {
      issues.push({ title: 'Input Reflected in Page', description: `URL parameter "${key}" value reflected in page content. Potential reflected XSS.`, severity: 'high', recommendation: 'HTML-encode all user input before rendering. Use Content Security Policy.' });
      break;
    }
  }
  return issues;
}

function checkInputType() {
  const issues = [];
  const passwordInputs = document.querySelectorAll('input[name*="password"], input[name*="passwd"]');
  for (const i of passwordInputs) {
    if (i.type !== 'password') {
      issues.push({ title: 'Password Input Not Type=password', description: `Password field "${i.name}" uses type="${i.type}" instead of type="password".`, severity: 'high', recommendation: 'Use type="password" for all password input fields.' });
      break;
    }
  }
  return issues;
}

function checkInsertAdjacentHTML() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/insertAdjacentHTML/i.test(scripts)) {
    issues.push({ title: 'insertAdjacentHTML Usage', description: 'insertAdjacentHTML() found. Similar to innerHTML, it\'s an XSS sink.', severity: 'medium', recommendation: 'Use insertAdjacentText() or createElement() instead. Sanitize HTML input with DOMPurify.' });
  }
  return issues;
}

function checkInstallScripts() { return []; }

function checkInsufficientEntropy() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Math\.random\s*\(\).*(?:token|key|id|session|nonce|salt|password)/i.test(scripts)) {
    issues.push({ title: 'Insufficient Entropy (Math.random)', description: 'Math.random() used for security-sensitive value generation. It is not cryptographically secure.', severity: 'high', recommendation: 'Use crypto.getRandomValues() or Web Crypto API for security-sensitive random values.' });
  }
  return issues;
}

function checkIntegerOverflow() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/parseInt\s*\(.*(?:price|amount|quantity|total|balance)/i.test(scripts)) {
    if (!/BigInt|Number\.isSafeInteger|Number\.MAX_SAFE_INTEGER/i.test(scripts)) {
      issues.push({ title: 'Integer Overflow Risk', description: 'parseInt used for financial/quantity values without safe integer checks.', severity: 'medium', recommendation: 'Use Number.isSafeInteger() checks or BigInt for large number handling.' });
    }
  }
  return issues;
}

function checkIntegrityMonitoring() { return []; }

function checkInternalIPs() {
  const issues = [];
  const html = document.documentElement ? document.documentElement.innerHTML.slice(0, 20000) : '';
  const ips = html.match(/(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/g);
  if (ips && ips.length > 0) {
    issues.push({ title: 'Internal IP Addresses Exposed', description: `Internal IP address(es) found in page content: ${[...new Set(ips)].slice(0, 3).join(', ')}`, severity: 'medium', recommendation: 'Remove internal IP addresses from client-facing content.' });
  }
  return issues;
}

function checkInternalURLs() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:http:\/\/|https:\/\/)(?:internal|intranet|corp|staging|dev|test|local)\./i.test(scripts)) {
    issues.push({ title: 'Internal URLs in Client Code', description: 'Internal/corporate URLs found in JavaScript code.', severity: 'high', recommendation: 'Remove internal environment URLs from production client code.' });
  }
  return issues;
}

function checkIPv6Config() { return []; }
function checkJITAccess() { return []; }

function checkJQueryHTML() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\$\s*\(\s*['"]<|\.html\s*\(|\.append\s*\(\s*['"]<|\.prepend\s*\(\s*['"]</i.test(scripts)) {
    if (/\$\s*\(\s*(?:location|user|input|data|param|response)/i.test(scripts) || /\.html\s*\(\s*(?:data|response|user|input)/i.test(scripts)) {
      issues.push({ title: 'jQuery HTML Injection Risk', description: 'jQuery used to inject potentially user-controlled HTML content.', severity: 'high', recommendation: 'Use .text() instead of .html(). Sanitize user input before DOM insertion.' });
    }
  }
  return issues;
}

function checkJQuerySRI() {
  const issues = [];
  const jq = document.querySelector('script[src*="jquery"]');
  if (jq && !jq.integrity && /cdn|cdnjs|unpkg|jsdelivr|ajax\.googleapis|code\.jquery/i.test(jq.src)) {
    issues.push({ title: 'jQuery Loaded Without SRI', description: 'jQuery loaded from CDN without Subresource Integrity.', severity: 'medium', recommendation: 'Add integrity attribute to jQuery script tag.' });
  }
  return issues;
}

function checkJSComments() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/\/\s*(?:TODO|FIXME|HACK|BUG|XXX|TEMP|REMOVE|password|secret|key|api|internal|sql|admin)/im.test(scripts) ||
      /\/\*[\s\S]*?(?:password|secret|key|token|credential|internal)[\s\S]*?\*\//i.test(scripts)) {
    issues.push({ title: 'Sensitive Info in JS Comments', description: 'JavaScript comments contain sensitive or debug information.', severity: 'medium', recommendation: 'Strip comments from production JavaScript bundles.' });
  }
  return issues;
}

function checkJSONInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/JSON\.stringify.*\+|'\s*\+\s*.*JSON|`.*\$\{.*JSON/i.test(scripts)) {
    issues.push({ title: 'JSON Injection Risk', description: 'JSON construction via string concatenation detected, risking injection.', severity: 'medium', recommendation: 'Use JSON.stringify() for safe JSON construction. Never concatenate user input into JSON strings.' });
  }
  return issues;
}

function checkJWTAlgorithmConfusion() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/jwt|jsonwebtoken/i.test(scripts) && /algorithms?\s*:\s*\[/i.test(scripts)) {
    if (/HS256.*RS256|RS256.*HS256|algorithms.*\[.*,/i.test(scripts)) {
      issues.push({ title: 'JWT Algorithm Confusion Risk', description: 'Multiple JWT algorithms accepted, risking algorithm confusion attacks.', severity: 'critical', recommendation: 'Accept only one JWT algorithm. Never allow algorithm switching.' });
    }
  }
  return issues;
}

function checkJWTAudience() { return []; }

function checkJWTExpiration() {
  const issues = [];
  try {
    const storage = [localStorage, sessionStorage];
    for (const s of storage) {
      for (let i = 0; i < s.length; i++) {
        const val = s.getItem(s.key(i)) || '';
        if (/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\./i.test(val)) {
          try {
            const payload = JSON.parse(atob(val.split('.')[1]));
            if (payload.exp && payload.exp * 1000 < Date.now()) {
              issues.push({ title: 'Expired JWT in Storage', description: 'Expired JWT token found in browser storage.', severity: 'medium', recommendation: 'Implement token refresh logic. Remove expired tokens from storage.' });
            }
            if (payload.exp && (payload.exp - (payload.iat || 0)) > 86400) {
              issues.push({ title: 'JWT Long Expiration', description: 'JWT has expiration longer than 24 hours.', severity: 'medium', recommendation: 'Use short-lived JWTs (15-60 minutes) with refresh tokens.' });
            }
          } catch(_) {}
          break;
        }
      }
    }
  } catch (_) {}
  return issues;
}

function checkJWTExpirationDuration() {
  return checkJWTExpiration();
}

function checkJWTInLocalStorage() {
  const issues = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const val = localStorage.getItem(key) || '';
      if (/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\./i.test(val)) {
        issues.push({ title: 'JWT Stored in localStorage', description: `JWT found in localStorage key "${key}". Vulnerable to XSS attacks.`, severity: 'high', recommendation: 'Store JWTs in httpOnly cookies instead of localStorage. Use short-lived tokens.' });
        break;
      }
    }
  } catch (_) {}
  return issues;
}

function checkJWTIssuer() { return []; }

function checkJWTJKU() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/jku|jwks_uri|x5u/i.test(scripts) && /jwt|jsonwebtoken/i.test(scripts)) {
    issues.push({ title: 'JWT JKU/X5U Header Usage', description: 'JWT with JKU or X5U header detected. Verify the URL is not user-controllable.', severity: 'high', recommendation: 'Hardcode JWKS URL server-side. Never use JKU/X5U headers from untrusted tokens.' });
  }
  return issues;
}

function checkJWTKidInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/kid.*header|header.*kid/i.test(scripts) && /jwt|token/i.test(scripts)) {
    issues.push({ title: 'JWT KID Injection Risk', description: 'JWT KID (Key ID) header processing detected. May be vulnerable to injection.', severity: 'high', recommendation: 'Validate KID values against an allowlist. Never use KID in file paths or SQL queries.' });
  }
  return issues;
}

function checkJWTLocalStorage() {
  return checkJWTInLocalStorage();
}

function checkJWTNoneAlgorithm() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/algorithm\s*[:=]\s*['"]none['"]/i.test(scripts) || /alg.*none/i.test(scripts)) {
    issues.push({ title: 'JWT "none" Algorithm Accepted', description: 'JWT configuration may accept "none" algorithm, bypassing signature verification.', severity: 'critical', recommendation: 'Never accept the "none" algorithm. Always verify JWT signatures.' });
  }
  return issues;
}

function checkJWTSensitiveData() {
  const issues = [];
  try {
    const storage = [localStorage, sessionStorage];
    for (const s of storage) {
      for (let i = 0; i < s.length; i++) {
        const val = s.getItem(s.key(i)) || '';
        if (/^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\./i.test(val)) {
          try {
            const payload = JSON.parse(atob(val.split('.')[1]));
            const sensitive = ['password', 'secret', 'ssn', 'credit_card', 'card_number'];
            for (const k of sensitive) {
              if (payload[k]) {
                issues.push({ title: 'Sensitive Data in JWT Payload', description: `JWT payload contains sensitive field "${k}". JWTs are only encoded, not encrypted.`, severity: 'critical', recommendation: 'Never include sensitive data (passwords, SSNs, credit cards) in JWT payloads.' });
                break;
              }
            }
          } catch (_) {}
          break;
        }
      }
    }
  } catch (_) {}
  return issues;
}

function checkJWTSignatureVerification() { return []; }

function checkJWTWeakKey() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/jwt|jsonwebtoken/i.test(scripts)) {
    if (/secret\s*[:=]\s*['"](?:.{1,15})['"]/i.test(scripts)) {
      issues.push({ title: 'JWT Weak Secret Key', description: 'JWT signing with a short/weak secret key detected.', severity: 'critical', recommendation: 'Use a strong, random secret key of at least 256 bits for JWT signing.' });
    }
  }
  return issues;
}

function checkJWTX5U() {
  return checkJWTJKU();
}

function checkK8sAdmission() { return []; }
function checkK8sAPIExposure() { return []; }
function checkK8sAuditLogging() { return []; }

function checkK8sDashboard() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/kubernetes.*dashboard|k8s.*dashboard/i.test(body)) {
    issues.push({ title: 'Kubernetes Dashboard Exposed', description: 'Kubernetes Dashboard reference detected on page.', severity: 'critical', recommendation: 'Restrict Kubernetes Dashboard access to internal networks with strong authentication.' });
  }
  return issues;
}

function checkK8sNetworkPolicy() { return []; }
function checkK8sNodeHardening() { return []; }
function checkK8sRBAC() { return []; }
function checkK8sSecretsEncryption() { return []; }
function checkKeyAccessLogging() { return []; }
function checkKeyBackup() { return []; }
function checkKeyCeremony() { return []; }
function checkKeyDestruction() { return []; }
function checkKeyEscrow() { return []; }
function checkKeyExpiration() { return []; }
function checkKeyFilePermissions() { return []; }
function checkKeyGenerationRNG() { return []; }

function checkKeyInLogs() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/console\.(log|debug|info).*(?:key|secret|token|password|credential)/i.test(scripts)) {
    issues.push({ title: 'Cryptographic Key/Secret in Logs', description: 'Console logging of potential keys or secrets detected.', severity: 'high', recommendation: 'Never log cryptographic keys, secrets, or tokens. Use structured logging with redaction.' });
  }
  return issues;
}

function checkKeyInMemory() { return []; }
function checkKeyRevocation() { return []; }

function checkKeyRotation() {
  const issues = [];
  // Server-side advisory
  return issues;
}

function checkKeySeparation() { return []; }

function checkKeysInConfig() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/config\s*[:=]\s*\{[\s\S]*?(?:key|secret|password|token)\s*[:=]\s*['"][a-zA-Z0-9+\/=_-]{10,}['"]/i.test(scripts)) {
    issues.push({ title: 'Keys/Secrets in Config Object', description: 'Configuration object contains keys or secrets in client-side code.', severity: 'critical', recommendation: 'Move secrets to server-side configuration. Use environment variables.' });
  }
  return issues;
}

function checkKeysInDocker() { return []; }

function checkKeysInEnv() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/process\.env\.(SECRET|KEY|PASSWORD|TOKEN|PRIVATE|DATABASE_URL)/i.test(scripts)) {
    issues.push({ title: 'Secret Env Vars in Client Bundle', description: 'Server-side environment variables (secrets, keys) leaked into client-side bundle.', severity: 'critical', recommendation: 'Only expose public env vars to client builds. Use NEXT_PUBLIC_ or VITE_ prefixes for client values.' });
  }
  return issues;
}

function checkKeysInGit() { return []; }
