// Batch 6: checkOptionsMethod through checkReproducibleBuilds

function checkOptionsMethod() { return []; }

function checkORMInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/sequelize|typeorm|prisma|knex|mongoose/i.test(scripts) && /\$where|raw\s*\(|query\s*\(/i.test(scripts)) {
    issues.push({ title: 'ORM Raw Query Usage', description: 'Raw/un-parameterized ORM query detected in client code.', severity: 'high', recommendation: 'Use parameterized ORM methods. Avoid raw queries with user input.' });
  }
  return issues;
}

function checkOrphanedAccounts() { return []; }
function checkOutdatedBaseImage() { return []; }

function checkOutdatedCryptoLib() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  for (const s of scripts) {
    const src = s.src || '';
    if (/crypto-?js[@\/](?:[12]\.|3\.[0-2])/i.test(src) || /forge[@\/]0\./i.test(src) || /sjcl\.js/i.test(src)) {
      issues.push({ title: 'Outdated Cryptography Library', description: 'Outdated version of a cryptography library detected.', severity: 'high', recommendation: 'Update cryptography libraries to the latest version.' });
      break;
    }
  }
  return issues;
}

function checkOutdatedDependencies() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const patterns = [
    { re: /jquery[@\/](?:1\.\d|2\.[0-2])/i, lib: 'jQuery < 3.0' },
    { re: /angular[@\/]1\./i, lib: 'AngularJS 1.x' },
    { re: /bootstrap[@\/][23]\./i, lib: 'Bootstrap 2.x/3.x' },
    { re: /lodash[@\/][0-3]\./i, lib: 'Lodash < 4.0' },
    { re: /moment[@\/]2\.\d\./i, lib: 'Moment.js (deprecated)' },
  ];
  for (const s of scripts) {
    for (const p of patterns) {
      if (p.re.test(s.src || '')) {
        issues.push({ title: 'Outdated Dependency', description: `Outdated library detected: ${p.lib}`, severity: 'medium', recommendation: `Update ${p.lib} to the latest version or replace with a maintained alternative.` });
      }
    }
  }
  return issues;
}

function checkOwnershipTransfer() { return []; }
function checkPackageIntegrity() { return []; }

function checkPackageJsonAccessible() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  if (links.some(l => /package\.json|package-lock\.json|yarn\.lock/i.test(l))) {
    issues.push({ title: 'package.json Accessible', description: 'Package manifest file linked on page, exposing dependency information.', severity: 'medium', recommendation: 'Block public access to package.json and lock files.' });
  }
  return issues;
}

function checkPaddingOracle() { return []; }

function checkPaginationCount() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:limit|per_page|page_size|count)\s*[:=]\s*(?:1000|9999|999999)/i.test(scripts) || /(?:limit|per_page|page_size)\s*[:=].*(?:input|param|user|query)/i.test(scripts)) {
    issues.push({ title: 'Unbounded Pagination', description: 'Large or user-controlled pagination limits detected.', severity: 'medium', recommendation: 'Cap pagination limits (e.g., max 100). Validate server-side.' });
  }
  return issues;
}

function checkParameterTampering() {
  const issues = [];
  const hidden = document.querySelectorAll('input[type="hidden"]');
  for (const h of hidden) {
    const name = (h.name || '').toLowerCase();
    if (/price|amount|total|discount|tax|shipping|role|admin|permission/i.test(name)) {
      issues.push({ title: 'Parameter Tampering Risk', description: `Hidden field "${h.name}" controls a sensitive value that can be manipulated.`, severity: 'high', recommendation: 'Validate all pricing, permissions, and business logic server-side. Never trust client-supplied values.' });
      break;
    }
  }
  return issues;
}

function checkPasswordAutocomplete() {
  const issues = [];
  const pwFields = document.querySelectorAll('input[type="password"][autocomplete="on"], input[type="password"]:not([autocomplete])');
  // New password fields should have autocomplete="new-password", current should have "current-password"
  const loginPw = document.querySelectorAll('input[type="password"][autocomplete="off"]');
  if (loginPw.length > 0) {
    issues.push({ title: 'Password Autocomplete Off', description: 'Password fields have autocomplete="off", preventing password managers.', severity: 'low', recommendation: 'Use autocomplete="current-password" or "new-password" to support password managers.' });
  }
  return issues;
}

function checkPasswordComplexity() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const pwForms = document.querySelectorAll('form[action*="register"], form[action*="signup"], form[action*="password"]');
  if (pwForms.length > 0 && !/(?:password.*(?:length|min|max|pattern|strength|complex)|(?:upper|lower|digit|special))/i.test(scripts)) {
    issues.push({ title: 'No Password Complexity Validation', description: 'Registration/password form without visible complexity requirements.', severity: 'medium', recommendation: 'Enforce password complexity: minimum 8 characters, mix of character types. Use zxcvbn for strength checking.' });
  }
  return issues;
}

function checkPasswordExpiration() { return []; }
function checkPasswordExpirationFrequent() { return []; }

function checkPasswordHints() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  if (/password\s*hint|security\s*question|what.?is.?your.?mother|pet.?name|born.?in|maiden.?name/i.test(body)) {
    issues.push({ title: 'Password Hints/Security Questions', description: 'Security questions or password hints found. These are weak authentication recovery methods.', severity: 'medium', recommendation: 'Replace security questions with proper MFA and account recovery via email/phone verification.' });
  }
  return issues;
}

function checkPasswordHistory() { return []; }

function checkPasswordHTTP() {
  const issues = [];
  const pwFields = document.querySelectorAll('input[type="password"]');
  if (pwFields.length > 0 && window.location.protocol === 'http:') {
    issues.push({ title: 'Password Over HTTP', description: 'Password field on HTTP page. Credentials transmitted in plaintext.', severity: 'critical', recommendation: 'Always use HTTPS for pages with password fields. Enable HSTS.' });
  }
  return issues;
}

function checkPasswordInURL() {
  const issues = [];
  const url = window.location.href;
  if (/[?&](?:password|passwd|pwd|pass)=/i.test(url)) {
    issues.push({ title: 'Password in URL', description: 'Password parameter found in URL. Visible in browser history, logs, and referrer.', severity: 'critical', recommendation: 'Always send passwords in POST body, never in URL parameters.' });
  }
  return issues;
}

function checkPasswordLength() {
  const issues = [];
  const pwFields = document.querySelectorAll('input[type="password"]');
  for (const pw of pwFields) {
    const max = pw.getAttribute('maxlength');
    if (max && parseInt(max) < 20) {
      issues.push({ title: 'Short Maximum Password Length', description: `Password field has maxlength="${max}". May truncate strong passwords.`, severity: 'medium', recommendation: 'Allow passwords up to at least 64 characters (NIST recommendation).' });
      break;
    }
    const min = pw.getAttribute('minlength');
    if (min && parseInt(min) < 8) {
      issues.push({ title: 'Low Minimum Password Length', description: `Password field has minlength="${min}". Minimum 8 characters recommended.`, severity: 'medium', recommendation: 'Set minimum password length to at least 8 characters (12+ preferred).' });
      break;
    }
  }
  return issues;
}

function checkPasswordLogging() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/console\.\w+.*password|log.*password/i.test(scripts)) {
    issues.push({ title: 'Password Logging', description: 'Password may be logged to console.', severity: 'critical', recommendation: 'Never log passwords. Redact sensitive fields from all logging.' });
  }
  return issues;
}

function checkPasswordMaxLength() {
  const issues = [];
  const pwFields = document.querySelectorAll('input[type="password"]');
  for (const pw of pwFields) {
    const max = pw.getAttribute('maxlength');
    if (max && parseInt(max) > 0 && parseInt(max) < 64) {
      issues.push({ title: 'Restrictive Password Max Length', description: `Password field limits to ${max} characters. May indicate plain-text storage.`, severity: 'medium', recommendation: 'Allow passwords up to 64+ characters. Hash passwords (no need for length limits with hashing).' });
      break;
    }
  }
  return issues;
}

function checkPasswordResetExpiration() { return []; }
function checkPasswordResetRateLimit() { return []; }
function checkPasswordResetReuse() { return []; }
function checkPasswordResetVerification() { return []; }
function checkPasswordSalt() { return []; }

function checkPasswordsInLogs() {
  return checkPasswordLogging();
}

function checkPasswordStrengthMeter() {
  const issues = [];
  const pwForms = document.querySelectorAll('form[action*="register"], form[action*="signup"], form[action*="password"]');
  if (pwForms.length > 0) {
    const body = document.body ? document.body.innerHTML.slice(0, 10000) : '';
    if (!/strength|meter|zxcvbn|password.*(?:weak|medium|strong|score)/i.test(body)) {
      issues.push({ title: 'No Password Strength Meter', description: 'Password form without visual strength indicator.', severity: 'low', recommendation: 'Add a password strength meter (e.g., zxcvbn) to guide users toward strong passwords.' });
    }
  }
  return issues;
}

function checkPathTraversal() {
  const issues = [];
  const params = new URLSearchParams(window.location.search);
  for (const [key, value] of params) {
    if (/file|path|page|doc|dir|folder|template|include/i.test(key)) {
      if (/\.\.|%2e%2e|%252e/i.test(value)) {
        issues.push({ title: 'Path Traversal in URL', description: `URL parameter "${key}" contains path traversal sequences.`, severity: 'critical', recommendation: 'Validate and sanitize file paths. Use allowlists for accessible resources.' });
      }
      break;
    }
  }
  return issues;
}

function checkPaymentGatewayScripts() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
  const paymentScripts = scripts.filter(s => /stripe|paypal|braintree|adyen|square|checkout\.com|razorpay/i.test(s));
  for (const s of paymentScripts) {
    const el = document.querySelector(`script[src="${s}"]`);
    if (el && !el.integrity) {
      issues.push({ title: 'Payment Script Without SRI', description: 'Payment gateway script loaded without Subresource Integrity.', severity: 'high', recommendation: 'Add SRI integrity attribute to payment gateway scripts.' });
      break;
    }
  }
  return issues;
}

function checkPaymentRequestAPI() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/PaymentRequest/i.test(scripts) && window.location.protocol !== 'https:') {
    issues.push({ title: 'Payment Request API Over HTTP', description: 'Payment Request API used on non-HTTPS page.', severity: 'critical', recommendation: 'Payment Request API requires HTTPS. Ensure all payment pages use HTTPS.' });
  }
  return issues;
}

function checkPDFSSRF() { return []; }
function checkPeerDependencies() { return []; }
function checkPermissionAudit() { return []; }
function checkPermissionRevocation() { return []; }

function checkPermissiveCORS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Access-Control-Allow-Origin.*\*/i.test(scripts)) {
    if (/credentials|cookie|authorization/i.test(scripts)) {
      issues.push({ title: 'Permissive CORS with Credentials', description: 'Wildcard CORS origin with credential usage detected.', severity: 'critical', recommendation: 'Never use * with credentials. Whitelist specific origins.' });
    }
  }
  return issues;
}

function checkPhantomDependencies() { return []; }

function checkPhoneNumbers() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  // Look for exposed phone numbers in HTML comments or data attributes
  const html = document.documentElement.innerHTML.slice(0, 20000);
  const comments = [];
  const walk = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
  let n; while (n = walk.nextNode()) comments.push(n.textContent);
  if (/(?:\+1|1)?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g.test(comments.join(''))) {
    issues.push({ title: 'Phone Numbers in HTML Comments', description: 'Phone numbers found in HTML comments.', severity: 'low', recommendation: 'Remove personal phone numbers from HTML comments.' });
  }
  return issues;
}

function checkPHPCodeInjection() { return []; }

function checkPhpInfo() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  if (links.some(l => /phpinfo/i.test(l))) {
    issues.push({ title: 'phpinfo() Page Exposed', description: 'Link to phpinfo() page found. Exposes server configuration details.', severity: 'high', recommendation: 'Remove phpinfo() pages from production servers.' });
  }
  const body = document.body ? document.body.innerHTML.slice(0, 5000) : '';
  if (/phpinfo\(\)|PHP\s+Version\s+\d+\.\d+|Configuration\s+File.*php\.ini/i.test(body)) {
    issues.push({ title: 'phpinfo() Output on Page', description: 'phpinfo() output detected on current page.', severity: 'critical', recommendation: 'Remove phpinfo() calls from production code.' });
  }
  return issues;
}

function checkPhysicalAddress() { return []; }
function checkPIIEncryption() { return []; }
function checkPIIIdentification() { return []; }
function checkPIIInLogs() { return []; }

function checkPlainTextPasswords() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/password\s*[:=]\s*['"][^'"]{3,}['"]|passwd\s*[:=]\s*['"][^'"]{3,}['"]/i.test(scripts)) {
    issues.push({ title: 'Plain Text Password in Code', description: 'Hardcoded plain text password found in JavaScript.', severity: 'critical', recommendation: 'Remove hardcoded passwords. Use environment variables and secure credential management.' });
  }
  return issues;
}

function checkPodSecurityPolicy() { return []; }

function checkPredictableAPIIDs() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\/.*\/\d{1,6}(?:\/|$|['"])/i.test(scripts)) {
    issues.push({ title: 'Predictable API IDs', description: 'Small sequential numeric IDs used in API endpoints.', severity: 'medium', recommendation: 'Use UUIDs or non-sequential IDs for API endpoints. Verify access server-side.' });
  }
  return issues;
}

function checkPredictableCSRFToken() {
  const issues = [];
  const tokens = document.querySelectorAll('input[name*="csrf"], input[name*="token"]');
  for (const t of tokens) {
    const val = t.value || '';
    if (val.length < 16) {
      issues.push({ title: 'Short CSRF Token', description: `CSRF token length ${val.length} may be too short for adequate security.`, severity: 'medium', recommendation: 'Use CSRF tokens of at least 32 characters generated with a CSPRNG.' });
      break;
    }
  }
  return issues;
}

function checkPredictableHashInput() { return []; }
function checkPredictableSeed() { return []; }

function checkPredictableSessionID() {
  const issues = [];
  const cookies = document.cookie.split(';');
  for (const c of cookies) {
    const [name, value] = c.split('=').map(s => s.trim());
    if (/session|sess|sid/i.test(name) && value && value.length < 16) {
      issues.push({ title: 'Short Session ID', description: `Session cookie "${name}" value is only ${value.length} characters. May be predictable.`, severity: 'high', recommendation: 'Use session IDs of at least 128 bits (32 hex characters) generated with CSPRNG.' });
      break;
    }
  }
  return issues;
}

function checkPredictableUploadNames() { return []; }
function checkPreReleaseVersions() { return []; }

function checkPriceValidation() {
  const issues = [];
  const hidden = document.querySelectorAll('input[type="hidden"]');
  for (const h of hidden) {
    if (/price|amount|total|cost|fee|charge/i.test(h.name || '')) {
      issues.push({ title: 'Client-Side Price Value', description: `Price/amount in hidden field "${h.name}" can be tampered.`, severity: 'high', recommendation: 'Calculate all prices server-side. Never trust client-submitted price values.' });
      break;
    }
  }
  return issues;
}

function checkPrivateKeyPassphrase() { return []; }
function checkPrivateRegistry() { return []; }
function checkPrivilegedContainer() { return []; }

function checkProfilerAccess() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000) : '';
  if (/xdebug|xhprof|blackfire|newrelic|profiler|debug_toolbar/i.test(body)) {
    issues.push({ title: 'Profiler/Debug Toolbar', description: 'Profiling or debug toolbar references found on page.', severity: 'high', recommendation: 'Disable profiling tools and debug toolbars in production.' });
  }
  return issues;
}

function checkPrototypePollution() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:__proto__|constructor\s*\.\s*prototype|Object\.assign\s*\(\s*\{)/i.test(scripts)) {
    if (/merge|extend|defaultsDeep|set\s*\(|deepCopy|deepMerge/i.test(scripts)) {
      issues.push({ title: 'Prototype Pollution Risk', description: 'Deep merge/extend operations found that may be vulnerable to prototype pollution.', severity: 'high', recommendation: 'Use Object.create(null) for dictionaries. Validate property names. Use libraries with prototype pollution protection.' });
    }
  }
  return issues;
}

function checkPrototypePollutionDep() { return []; }
function checkProvenance() { return []; }
function checkPseudonymization() { return []; }

function checkPublicStorage() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\.s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net/i.test(scripts)) {
    if (/public|anonymous|no-auth/i.test(scripts)) {
      issues.push({ title: 'Public Cloud Storage', description: 'Public cloud storage bucket reference found in code.', severity: 'high', recommendation: 'Restrict cloud storage access. Use signed URLs for private content.' });
    }
  }
  return issues;
}

function checkPushMFAFatigue() { return []; }

function checkPushNotifications() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Notification\.requestPermission|PushManager|push.*subscribe/i.test(scripts)) {
    if (window.location.protocol !== 'https:') {
      issues.push({ title: 'Push Notifications Over HTTP', description: 'Push notification registration on non-HTTPS page.', severity: 'medium', recommendation: 'Push notifications require HTTPS. Ensure service worker runs on HTTPS.' });
    }
  }
  return issues;
}

function checkPWAInstallPrompt() {
  const issues = [];
  const link = document.querySelector('link[rel="manifest"]');
  if (link) {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    if (/beforeinstallprompt/i.test(scripts)) {
      // PWA install prompt - check security
      if (window.location.protocol !== 'https:') {
        issues.push({ title: 'PWA Install Prompt Over HTTP', description: 'PWA install prompt on non-HTTPS page.', severity: 'medium', recommendation: 'PWAs require HTTPS. Serve all PWA assets over HTTPS.' });
      }
    }
  }
  return issues;
}

function checkPythonEvalExec() { return []; }

function checkQuantityValidation() {
  const issues = [];
  const qtyInputs = document.querySelectorAll('input[name*="quantity"], input[name*="qty"], input[name*="count"]');
  for (const q of qtyInputs) {
    if (!q.getAttribute('min') || !q.getAttribute('max')) {
      issues.push({ title: 'Quantity Input Without Bounds', description: `Quantity field "${q.name}" lacks min/max constraints.`, severity: 'medium', recommendation: 'Add min and max attributes to quantity inputs. Validate quantities server-side.' });
      break;
    }
  }
  return issues;
}

function checkRainbowTable() { return []; }

function checkRandFunction() {
  return checkMathRandom();
}

function checkRandomReuse() { return []; }

function checkRangeAPI() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/document\.createRange|Range\(\)/i.test(scripts)) {
    if (/innerHTML|extractContents|insertNode/i.test(scripts)) {
      issues.push({ title: 'Range API DOM Manipulation', description: 'Range API used with innerHTML or DOM insertion. Potential for injection.', severity: 'low', recommendation: 'Sanitize content before inserting via Range API.' });
    }
  }
  return issues;
}

function checkRateLimitBypass() { return []; }

function checkRateLimitHeaders() {
  // Can detect from script context
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/X-RateLimit|RateLimit-Remaining|Retry-After/i.test(scripts)) {
    // Rate limit headers handled - good
  }
  return issues;
}

function checkRBACImplementation() { return []; }

function checkRC4() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/rc4|arcfour|ARC4/i.test(scripts)) {
    issues.push({ title: 'RC4 Cipher Usage', description: 'RC4 cipher detected. RC4 is cryptographically broken.', severity: 'critical', recommendation: 'Replace RC4 with AES-GCM or ChaCha20-Poly1305.' });
  }
  return issues;
}

function checkRDSEncryption() { return []; }
function checkRDSPublic() { return []; }

function checkReactDangerouslySetInnerHTML() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/dangerouslySetInnerHTML/i.test(scripts)) {
    issues.push({ title: 'React dangerouslySetInnerHTML', description: 'dangerouslySetInnerHTML usage detected. Direct XSS risk if input is not sanitized.', severity: 'high', recommendation: 'Avoid dangerouslySetInnerHTML. Use DOMPurify to sanitize if absolutely needed.' });
  }
  return issues;
}

function checkReactDevTools() {
  const issues = [];
  if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    issues.push({ title: 'React DevTools Available', description: 'React DevTools hook detected. Attackers can inspect component state.', severity: 'low', recommendation: 'Consider disabling React DevTools in production using __REACT_DEVTOOLS_GLOBAL_HOOK__.inject = function() {};' });
  }
  return issues;
}

function checkReadmeAccessible() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  if (links.some(l => /readme\.md|readme\.txt|readme\.html/i.test(l))) {
    issues.push({ title: 'README Accessible', description: 'README file linked on page, potentially exposing project details.', severity: 'low', recommendation: 'Block public access to README files on production servers.' });
  }
  return issues;
}

function checkReDoS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const regexes = scripts.match(/new\s+RegExp\s*\([^)]*\)|\/[^\/]+\/[gimsuy]*/g) || [];
  for (const r of regexes) {
    if (/(\.\*){2}|\(\?[^)]*\)\+|\([^)]*\+\)\+|\([^)]*\*\)\*/i.test(r)) {
      issues.push({ title: 'ReDoS (Regular Expression DoS)', description: 'Potentially catastrophic regex pattern detected. May cause exponential backtracking.', severity: 'medium', recommendation: 'Review regex patterns for catastrophic backtracking. Use RE2 or limit input length.' });
      break;
    }
  }
  return issues;
}

function checkReDoSDep() { return []; }

function checkReflectedXSS() {
  const issues = [];
  const params = new URLSearchParams(window.location.search);
  const body = document.body ? document.body.innerHTML : '';
  for (const [key, value] of params) {
    if (value.length > 3 && body.includes(value)) {
      if (/<[a-z]/i.test(value) || /on\w+=|javascript:/i.test(value)) {
        issues.push({ title: 'Reflected XSS', description: `URL parameter "${key}" reflected in page with potential XSS payload.`, severity: 'critical', recommendation: 'HTML-encode all user input before rendering. Implement strict CSP.' });
        break;
      }
    }
  }
  return issues;
}

function checkRefreshTokenExpiration() { return []; }

function checkRefreshTokenRotation() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/refresh_token|refreshToken/i.test(scripts)) {
    if (!/rotat/i.test(scripts)) {
      issues.push({ title: 'No Refresh Token Rotation', description: 'Refresh token usage without visible rotation mechanism.', severity: 'medium', recommendation: 'Implement refresh token rotation. Issue new refresh token with each use.' });
    }
  }
  return issues;
}

function checkRegistrationRateLimit() { return []; }
function checkRegistryHTTPS() { return []; }
function checkRegistryMirror() { return []; }
function checkRegistrySecurity() { return []; }
function checkRepoTokenLeak() { return []; }
function checkReproducibleBuilds() { return []; }
