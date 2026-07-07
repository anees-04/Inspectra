// Batch 5: checkKeySplitting through checkOIDCNonce

function checkKeySplitting() { return []; }
function checkKeyVersioning() { return []; }
function checkKMSRotation() { return []; }
function checkLambdaPublic() { return []; }
function checkLambdaTimeout() { return []; }

function checkLanguagePathTraversal() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:lang|locale|language)\s*[:=].*(?:\.\.\/|\.\.\\|%2e%2e)/i.test(scripts)) {
    issues.push({ title: 'Language Parameter Path Traversal', description: 'Language/locale parameter may be vulnerable to path traversal.', severity: 'high', recommendation: 'Validate locale values against an allow list. Never use user-supplied locale in file paths.' });
  }
  return issues;
}

function checkLargePackage() { return []; }
function checkLatestTag() { return []; }

function checkLDAPInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/ldap|active\s*directory/i.test(scripts)) {
    issues.push({ title: 'LDAP Injection Risk', description: 'LDAP/Active Directory references found in client code.', severity: 'medium', recommendation: 'Sanitize all input used in LDAP queries. Use parameterized LDAP filters.' });
  }
  return issues;
}

function checkLeastPrivilege() { return []; }

function checkLFI() {
  const issues = [];
  const params = new URLSearchParams(window.location.search);
  for (const [key, value] of params) {
    if (/file|path|page|include|template|doc|load/i.test(key) && /\.\.\/|\.\.\\|%2e|etc\/passwd|boot\.ini/i.test(value)) {
      issues.push({ title: 'Local File Inclusion (LFI) Risk', description: `URL parameter "${key}" contains path traversal characters.`, severity: 'critical', recommendation: 'Validate file parameters against an allowlist. Never pass user input to file system operations.' });
      break;
    }
  }
  return issues;
}

function checkLicenseChangeMonitoring() { return []; }
function checkLicenseCompliance() { return []; }
function checkLicenseFile() { return []; }

function checkLiveChatSecurity() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
  if (scripts.some(s => /livechat|intercom|zendesk|drift|tawk|freshchat|crisp|olark/i.test(s))) {
    const noSRI = document.querySelectorAll('script[src*="livechat"]:not([integrity]), script[src*="intercom"]:not([integrity]), script[src*="zendesk"]:not([integrity]), script[src*="drift"]:not([integrity]), script[src*="tawk"]:not([integrity])');
    if (noSRI.length > 0) {
      issues.push({ title: 'Live Chat Without SRI', description: 'Live chat third-party script loaded without Subresource Integrity.', severity: 'low', recommendation: 'Add SRI to live chat scripts. Review data access permissions for chat providers.' });
    }
  }
  return issues;
}

function checkLocalStorageEncryption() {
  const issues = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const val = localStorage.getItem(key) || '';
      if (/token|auth|session|credential|password|secret/i.test(key) && val.length > 10) {
        if (!/^[a-f0-9]{64}$|^[a-zA-Z0-9+\/]{20,}={0,2}$/i.test(val)) {
          issues.push({ title: 'Unencrypted Sensitive Data in localStorage', description: `localStorage key "${key}" contains potentially sensitive unencrypted data.`, severity: 'high', recommendation: 'Encrypt sensitive data before storing in localStorage or use httpOnly cookies instead.' });
          break;
        }
      }
    }
  } catch (_) {}
  return issues;
}

function checkLocalStorageSensitive() {
  const issues = [];
  try {
    const sensitiveKeys = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (/password|secret|private|ssn|credit.?card|cvv|pin|dob|social.?security/i.test(key)) {
        sensitiveKeys.push(key);
      }
    }
    if (sensitiveKeys.length > 0) {
      issues.push({ title: 'Highly Sensitive Data in localStorage', description: `Sensitive keys found: ${sensitiveKeys.slice(0, 3).join(', ')}`, severity: 'critical', recommendation: 'Never store passwords, SSNs, or credit card numbers in localStorage.' });
    }
  } catch (_) {}
  return issues;
}

function checkLocationHrefAssignment() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:window\.)?location\.href\s*=\s*(?!['"]https?:)/i.test(scripts) ||
      /(?:window\.)?location\s*=\s*(?!['"]https?:)/i.test(scripts)) {
    issues.push({ title: 'Dynamic Location Assignment', description: 'location.href assigned from potentially user-controlled input. Open redirect or XSS risk.', severity: 'medium', recommendation: 'Validate redirect URLs against an allowlist. Use relative URLs when possible.' });
  }
  return issues;
}

function checkLockFile() { return []; }
function checkLogAnalysis() { return []; }
function checkLogEncryption() { return []; }

function checkLogFileAccess() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  if (links.some(l => /\.log$|\/logs\/|access_log|error_log|debug\.log/i.test(l))) {
    issues.push({ title: 'Log Files Accessible', description: 'Links to log files found on page.', severity: 'high', recommendation: 'Block public access to log files. Store logs outside the web root.' });
  }
  return issues;
}

function checkLogFilesAccessible() {
  return checkLogFileAccess();
}

function checkLoginCSRF() {
  const issues = [];
  const loginForms = document.querySelectorAll('form[action*="login"], form[action*="signin"], form[action*="auth"]');
  for (const form of loginForms) {
    const csrfField = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity"]');
    if (!csrfField) {
      issues.push({ title: 'Login Form Missing CSRF Token', description: 'Login form lacks CSRF protection. Vulnerable to login CSRF attacks.', severity: 'high', recommendation: 'Add CSRF token to login forms to prevent attackers from logging victims into attacker-controlled accounts.' });
      break;
    }
  }
  return issues;
}

function checkLogInjection() { return []; }

function checkLoginRateLimit() {
  const issues = [];
  const loginForms = document.querySelectorAll('form[action*="login"], form[action*="signin"], form[action*="auth"]');
  if (loginForms.length > 0) {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    if (!/rate.*limit|throttle|captcha|recaptcha|hcaptcha|turnstile|lockout|too.many.attempts/i.test(scripts + document.body.innerText.slice(0, 5000))) {
      issues.push({ title: 'No Login Rate Limiting Detected', description: 'Login form without visible rate limiting, CAPTCHA, or account lockout.', severity: 'medium', recommendation: 'Implement login rate limiting, account lockout, or CAPTCHA after failed attempts.' });
    }
  }
  return issues;
}

function checkLogIntegrity() { return []; }
function checkLogjam() { return []; }

function checkLogoutCSRF() {
  const issues = [];
  const logoutLinks = document.querySelectorAll('a[href*="logout"], a[href*="signout"]');
  if (logoutLinks.length > 0) {
    issues.push({ title: 'Logout via GET Link', description: 'Logout implemented as GET request link. Vulnerable to CSRF-based forced logout.', severity: 'low', recommendation: 'Implement logout as POST request with CSRF token.' });
  }
  return issues;
}

function checkLogoutInvalidation() { return []; }
function checkLogPathInjection() { return []; }
function checkLogRetention() { return []; }
function checkLogRotation() { return []; }

function checkLongPolling() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/long[_-]?poll|polling|setInterval.*(?:fetch|ajax|xhr)/i.test(scripts)) {
    issues.push({ title: 'Long Polling Detected', description: 'Long polling used instead of WebSockets or SSE. May indicate legacy architecture.', severity: 'info', recommendation: 'Consider upgrading to WebSockets or Server-Sent Events for better performance and security.' });
  }
  return issues;
}

function checkLowBcryptCost() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/bcrypt.*(?:rounds?|cost)\s*[:=]\s*(\d+)/i.test(scripts)) {
    const cost = parseInt(RegExp.$1);
    if (cost < 12) {
      issues.push({ title: 'Low bcrypt Cost Factor', description: `bcrypt cost factor set to ${cost}. Recommended minimum is 12.`, severity: 'medium', recommendation: 'Use bcrypt cost factor of at least 12 (ideally 14+) for password hashing.' });
    }
  }
  return issues;
}

function checkLowDownloads() { return []; }

function checkLowPBKDF2Iterations() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/pbkdf2.*iterations?\s*[:=]\s*(\d+)/i.test(scripts)) {
    const iterations = parseInt(RegExp.$1);
    if (iterations < 100000) {
      issues.push({ title: 'Low PBKDF2 Iterations', description: `PBKDF2 iterations set to ${iterations}. Recommended minimum is 600,000 for SHA-256.`, severity: 'medium', recommendation: 'Use at least 600,000 iterations for PBKDF2-SHA256 (OWASP 2023 recommendation).' });
    }
  }
  return issues;
}

function checkMaintainerCompromise() { return []; }
function checkMaliciousInstallScript() { return []; }
function checkManualDeploy() { return []; }

function checkMarkdownXSS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/marked|markdown|showdown|remarkable|markdown-it/i.test(scripts)) {
    if (!/sanitize|DOMPurify|xss|bleach/i.test(scripts)) {
      issues.push({ title: 'Markdown Rendering Without Sanitization', description: 'Markdown library used without visible sanitization. Risk of XSS through Markdown.', severity: 'high', recommendation: 'Sanitize rendered Markdown with DOMPurify. Disable raw HTML in Markdown parsers.' });
    }
  }
  return issues;
}

function checkMassAssignment() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Object\.assign\s*\(\s*(?:user|account|profile|model)/i.test(scripts) || /\.\.\.(?:req\.body|request\.body|data|payload|input)/i.test(scripts)) {
    issues.push({ title: 'Mass Assignment Risk', description: 'Object spread or Object.assign used with potentially untrusted input.', severity: 'high', recommendation: 'Explicitly whitelist allowed properties instead of mass-assigning from user input.' });
  }
  return issues;
}

function checkMasterKeyProtection() { return []; }

function checkMathRandom() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const count = (scripts.match(/Math\.random\s*\(\)/g) || []).length;
  if (count > 0) {
    issues.push({ title: 'Math.random() Usage', description: `Math.random() used ${count} time(s). Not cryptographically secure for tokens/keys.`, severity: 'medium', recommendation: 'Use crypto.getRandomValues() for security-sensitive random number generation.' });
  }
  return issues;
}

function checkMD5Usage() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/md5\s*\(|CryptoJS\.MD5|sparkmd5|js-md5/i.test(scripts)) {
    issues.push({ title: 'MD5 Hash Usage', description: 'MD5 hash algorithm detected. MD5 is cryptographically broken.', severity: 'high', recommendation: 'Replace MD5 with SHA-256 or SHA-3. Never use MD5 for passwords or security.' });
  }
  return issues;
}

function checkMemoryDumpAccess() { return []; }
function checkMemoryDumps() { return []; }
function checkMessageQueueSecurity() { return []; }

function checkMetadataManipulation() { return []; }

function checkMetaTags() {
  const issues = [];
  const robots = document.querySelector('meta[name="robots"]');
  if (!robots || !/noindex/i.test(robots.content || '')) {
    // Not necessarily an issue for public pages
  }
  const referrer = document.querySelector('meta[name="referrer"]');
  if (!referrer) {
    issues.push({ title: 'Missing Referrer Meta Tag', description: 'No meta referrer policy set. Sensitive data may leak in Referer headers.', severity: 'low', recommendation: 'Add <meta name="referrer" content="strict-origin-when-cross-origin"> to prevent data leakage.' });
  }
  return issues;
}

function checkMetaTagXSS() {
  const issues = [];
  const metas = document.querySelectorAll('meta[http-equiv="refresh"]');
  for (const m of metas) {
    const content = m.getAttribute('content') || '';
    if (/url\s*=\s*(?:javascript|data|vbscript):/i.test(content)) {
      issues.push({ title: 'Meta Tag XSS', description: 'Meta refresh tag with potentially malicious URL scheme (javascript:/data:).', severity: 'critical', recommendation: 'Only use HTTP(S) URLs in meta refresh tags.' });
      break;
    }
  }
  return issues;
}

function checkMethodOverride() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/X-HTTP-Method-Override|X-Method-Override|_method/i.test(scripts)) {
    issues.push({ title: 'HTTP Method Override', description: 'HTTP method override detected. May bypass security controls based on HTTP methods.', severity: 'medium', recommendation: 'Disable method override if not needed. Validate overridden methods server-side.' });
  }
  return issues;
}

function checkMetricsEndpoint() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000) : '';
  if (/\/metrics|\/prometheus|\/actuator\/metrics|\/health/i.test(body)) {
    issues.push({ title: 'Metrics Endpoint Reference', description: 'Reference to metrics/health endpoint found in page content.', severity: 'medium', recommendation: 'Restrict metrics endpoints to internal networks. Require authentication.' });
  }
  return issues;
}

function checkMFAAvailable() { return []; }
function checkMFABackupCodes() { return []; }

function checkMFABypass() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/mfa|two.?factor|2fa|totp|otp/i.test(scripts) && /skip|bypass|disable|remember/i.test(scripts)) {
    issues.push({ title: 'MFA Bypass Mechanism', description: 'MFA skip/bypass/remember mechanism detected in client code.', severity: 'high', recommendation: 'MFA bypass should be strictly controlled. Limit remember-device duration. Log MFA bypasses.' });
  }
  return issues;
}

function checkMFAEnforced() { return []; }
function checkMFAEnrollmentVerification() { return []; }
function checkMFAPrivileged() { return []; }

function checkMFAQRCodeHTTPS() {
  const issues = [];
  const images = document.querySelectorAll('img[src*="qr"], img[src*="totp"], img[alt*="QR"], canvas');
  if (images.length > 0 && window.location.protocol !== 'https:') {
    issues.push({ title: 'MFA QR Code Over HTTP', description: 'MFA QR code displayed over unencrypted HTTP connection.', severity: 'high', recommendation: 'Always serve MFA enrollment pages over HTTPS.' });
  }
  return issues;
}

function checkMFARateLimit() { return []; }
function checkMFARecovery() { return []; }

function checkMFARememberDevice() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/remember.*device|trusted.*device|skip.*mfa/i.test(scripts)) {
    issues.push({ title: 'MFA Remember Device', description: 'MFA "remember device" feature detected. Verify expiration and security.', severity: 'low', recommendation: 'Limit remember-device to 30 days max. Invalidate on password change. Bind to device fingerprint.' });
  }
  return issues;
}

function checkMFATokenExpiration() { return []; }

function checkMinification() {
  const issues = [];
  const scripts = document.querySelectorAll('script:not([src])');
  for (const s of scripts) {
    const t = s.textContent || '';
    if (t.length > 500) {
      const lines = t.split('\n').filter(l => l.trim().length > 0);
      const avgLen = t.length / Math.max(lines.length, 1);
      if (avgLen < 200 && lines.length > 20) {
        // Unminified - multiple short lines with proper formatting
        issues.push({ title: 'Unminified JavaScript', description: 'Inline JavaScript appears unminified. May expose code structure and logic.', severity: 'low', recommendation: 'Minify JavaScript in production to obscure code and reduce payload size.' });
        break;
      }
    }
  }
  return issues;
}

function checkMinifiedPackage() { return []; }

function checkMissingIV() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/AES|DES|Blowfish|cipher/i.test(scripts) && /ECB|(?:encrypt|cipher).*(?:key)\b/i.test(scripts)) {
    if (!/iv\b|initialization.?vector|CBC|GCM|CTR/i.test(scripts)) {
      issues.push({ title: 'Missing Initialization Vector (IV)', description: 'Encryption detected without IV usage. May use insecure ECB mode.', severity: 'high', recommendation: 'Always use a random IV with CBC/GCM modes. Never use ECB mode.' });
    }
  }
  return issues;
}

function checkMissingLicense() { return []; }

function checkMixedAuth() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const hasBearer = /Authorization.*Bearer/i.test(scripts);
  const hasCookieAuth = /withCredentials\s*[:=]\s*true|credentials\s*[:=]\s*['"]include/i.test(scripts);
  if (hasBearer && hasCookieAuth) {
    issues.push({ title: 'Mixed Authentication Methods', description: 'Both Bearer token and cookie-based authentication used. Inconsistent auth increases attack surface.', severity: 'medium', recommendation: 'Standardize on one authentication mechanism per application.' });
  }
  return issues;
}

function checkMixedContentCDN() {
  const issues = [];
  const scripts = document.querySelectorAll('script[src^="http://"], link[href^="http://"]');
  if (scripts.length > 0 && window.location.protocol === 'https:') {
    issues.push({ title: 'Mixed Content from CDN', description: `${scripts.length} resource(s) loaded over HTTP on HTTPS page.`, severity: 'high', recommendation: 'Load all CDN resources over HTTPS to prevent mixed content issues.' });
  }
  return issues;
}

function checkMonorepoDependencies() { return []; }
function checkMultipleAdmins() { return []; }

function checkMutationObserver() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/MutationObserver/i.test(scripts)) {
    // MutationObserver itself is not a vulnerability, just informational
  }
  return issues;
}

function checkMutationXSS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write/i.test(scripts)) {
    if (/DOMParser|createHTMLDocument|sanitize/i.test(scripts)) {
      // Using sanitization, but mutation XSS can bypass some sanitizers
      issues.push({ title: 'Mutation XSS Risk', description: 'HTML mutation via DOM parsing detected. Some sanitizers are vulnerable to mutation XSS.', severity: 'medium', recommendation: 'Use DOMPurify (latest version) for sanitization. Test with mutation XSS payloads.' });
    }
  }
  return issues;
}

function checkNamespaceSquatting() { return []; }
function checkNativeCodeAudit() { return []; }
function checkNativeModules() { return []; }

function checkNegativeNumbers() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:price|amount|quantity|total|balance|count)\s*[<>=!]/i.test(scripts)) {
    if (!/(?:price|amount|quantity|total|balance|count)\s*(?:<|<=)\s*0|Math\.abs|Math\.max.*0/i.test(scripts)) {
      issues.push({ title: 'No Negative Number Validation', description: 'Numeric values (price, quantity, etc.) not checked for negative values.', severity: 'medium', recommendation: 'Validate that quantities, prices, and amounts are non-negative on both client and server.' });
    }
  }
  return issues;
}

function checkNewPackage() { return []; }
function checkNodeVMEscape() { return []; }
function checkNoDocs() { return []; }
function checkNoKMS() { return []; }

function checkNoSalt() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/sha256|sha512|md5|hash/i.test(scripts) && /password/i.test(scripts)) {
    if (!/salt|bcrypt|argon|scrypt|pbkdf2/i.test(scripts)) {
      issues.push({ title: 'Hashing Without Salt', description: 'Password hashing detected without salt. Vulnerable to rainbow table attacks.', severity: 'high', recommendation: 'Use bcrypt, Argon2, or scrypt for password hashing. Always use unique salts.' });
    }
  }
  return issues;
}

function checkNoSQLInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\$where|\$gt|\$lt|\$ne|\$regex|\$exists|\$in.*user|mongodb|mongoose/i.test(scripts)) {
    issues.push({ title: 'NoSQL Injection Risk', description: 'MongoDB/NoSQL query operators found in client-side code.', severity: 'high', recommendation: 'Sanitize input used in NoSQL queries. Use parameterized queries.' });
  }
  return issues;
}

function checkNoTests() { return []; }
function checkNoTransitEncryption() { return []; }

function checkNullByteInjection() {
  const issues = [];
  const url = window.location.href;
  if (/%00|\\x00|\\0/.test(url)) {
    issues.push({ title: 'Null Byte in URL', description: 'Null byte character detected in URL. May be used for injection attacks.', severity: 'high', recommendation: 'Reject input containing null bytes. Sanitize all file path inputs.' });
  }
  return issues;
}

function checkNullCipher() { return []; }

function checkOAuthAccountLinking() { return []; }

function checkOAuthClientSecret() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/client.?secret\s*[:=]\s*['"][a-zA-Z0-9_-]{10,}['"]/i.test(scripts)) {
    issues.push({ title: 'OAuth Client Secret in Client Code', description: 'OAuth client secret exposed in client-side JavaScript.', severity: 'critical', recommendation: 'Never expose client secrets in client-side code. Use PKCE for public clients.' });
  }
  return issues;
}

function checkOAuthCovertRedirect() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/redirect_uri\s*[:=].*(?:location|user|input|param|window)/i.test(scripts)) {
    issues.push({ title: 'OAuth Covert Redirect', description: 'OAuth redirect_uri may be controlled by user input.', severity: 'high', recommendation: 'Validate redirect_uri against a whitelist of registered URLs. Use exact matching.' });
  }
  return issues;
}

function checkOAuthDeviceFlow() { return []; }
function checkOAuthDynamicRegistration() { return []; }

function checkOAuthHardcodedCreds() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/client_id\s*[:=]\s*['"][a-zA-Z0-9_-]{15,}['"]/i.test(scripts) && /client_secret\s*[:=]\s*['"][a-zA-Z0-9_-]{15,}['"]/i.test(scripts)) {
    issues.push({ title: 'Hardcoded OAuth Credentials', description: 'OAuth client_id and client_secret hardcoded in JavaScript.', severity: 'critical', recommendation: 'Remove OAuth secrets from client code. Use PKCE flow for public clients.' });
  }
  return issues;
}

function checkOAuthImplicitFlow() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/response_type\s*[:=]\s*['"]token['"]/i.test(scripts) || /implicit/i.test(scripts)) {
    issues.push({ title: 'OAuth Implicit Flow', description: 'OAuth Implicit flow detected. Tokens exposed in URL fragments.', severity: 'high', recommendation: 'Use Authorization Code flow with PKCE instead of Implicit flow.' });
  }
  return issues;
}

function checkOAuthIntrospection() { return []; }
function checkOAuthMetadata() { return []; }

function checkOAuthPKCE() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/oauth|authorize|authorization_code/i.test(scripts)) {
    if (!/code_challenge|code_verifier|pkce/i.test(scripts)) {
      issues.push({ title: 'OAuth Without PKCE', description: 'OAuth authorization code flow without PKCE (Proof Key for Code Exchange).', severity: 'medium', recommendation: 'Implement PKCE for all OAuth authorization code flows, especially for public clients.' });
    }
  }
  return issues;
}

function checkOAuthRedirectValidation() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/redirect_uri/i.test(scripts) && !/(?:whitelist|allowlist|validate|verify).*redirect/i.test(scripts)) {
    issues.push({ title: 'OAuth Redirect URI Validation', description: 'OAuth redirect_uri without visible validation.', severity: 'high', recommendation: 'Strictly validate redirect_uri against registered URIs. Use exact match, not prefix matching.' });
  }
  return issues;
}

function checkOAuthScope() { return []; }

function checkOAuthState() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/oauth|authorize/i.test(scripts) && !/state\s*[:=]|state_param|oauth.*state/i.test(scripts)) {
    issues.push({ title: 'OAuth Missing State Parameter', description: 'OAuth flow without state parameter for CSRF protection.', severity: 'high', recommendation: 'Always include a random state parameter in OAuth requests and verify on callback.' });
  }
  return issues;
}

function checkOAuthStateValidation() {
  return checkOAuthState();
}

function checkOAuthTokenLogging() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/console\.\w+.*(?:access_token|refresh_token|id_token|authorization)/i.test(scripts)) {
    issues.push({ title: 'OAuth Token Logging', description: 'OAuth tokens logged to console.', severity: 'high', recommendation: 'Never log OAuth tokens. Remove all debug logging of tokens in production.' });
  }
  return issues;
}

function checkObjectLevelAuth() { return []; }
function checkOCSPStapling() { return []; }

function checkOfflineFunctionality() {
  const issues = [];
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(regs => {
      // Async - can't return issues synchronously
    }).catch(() => {});
  }
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/serviceWorker\.register|caches\.open|cache\.addAll/i.test(scripts)) {
    if (/token|auth|session|credential/i.test(scripts)) {
      issues.push({ title: 'Offline Auth Data Caching', description: 'Service worker may cache authentication data for offline use.', severity: 'medium', recommendation: 'Exclude auth tokens and sensitive data from service worker cache.' });
    }
  }
  return issues;
}

function checkOGNLInjection() { return []; }

function checkOIDCNonce() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/openid|oidc|id_token/i.test(scripts) && !/nonce/i.test(scripts)) {
    issues.push({ title: 'OIDC Missing Nonce', description: 'OpenID Connect flow without nonce parameter. Vulnerable to replay attacks.', severity: 'medium', recommendation: 'Include a unique nonce in OIDC authentication requests and verify it in the ID token.' });
  }
  return issues;
}
