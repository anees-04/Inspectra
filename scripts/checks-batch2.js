// Batch 2: checkCentralizedLogging through checkDangerousObjectMethods

function checkCentralizedLogging() { return []; }

function checkCertChain() {
  const issues = [];
  if (window.location.protocol === 'http:') {
    issues.push({ title: 'No TLS Certificate (HTTP)', description: 'Site uses HTTP. Cannot verify certificate chain.', severity: 'high', recommendation: 'Enable HTTPS with a properly chained certificate.' });
  }
  return issues;
}

function checkCertExpiringSoon() {
  // Cannot check cert details from content script
  return [];
}

function checkCertHostnameMismatch() { return []; }
function checkCertKeySize() { return []; }
function checkCertSignatureAlg() { return []; }

function checkChangelogExposed() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /changelog|changes\.txt|changes\.md|release.notes/i.test(l))) {
    issues.push({ title: 'Changelog File Exposed', description: 'Link to changelog/release notes found. May reveal vulnerability fix timeline.', severity: 'low', recommendation: 'Remove changelog files from public web directories or restrict access.' });
  }
  return issues;
}

function checkCICDSecurity() { return []; }

function checkCircuitBreaker() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/circuit.?breaker|retry.*limit|backoff/i.test(scripts)) {
    issues.push({ title: 'No Circuit Breaker Pattern', description: 'API calls without circuit breaker or retry with backoff pattern.', severity: 'low', recommendation: 'Implement circuit breaker pattern for API calls to handle service failures gracefully.' });
  }
  return issues;
}

function checkClientAccessPolicy() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 5000).toLowerCase() : '';
  if (/clientaccesspolicy\.xml|crossdomain.*allow-access-from.*domain="\*"/i.test(body)) {
    issues.push({ title: 'Permissive Client Access Policy', description: 'Overly permissive client access policy detected.', severity: 'high', recommendation: 'Restrict client access policies to specific trusted domains.' });
  }
  return issues;
}

function checkClientCrypto() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/CryptoJS|sjcl|forge\.cipher|aes.*encrypt|des.*encrypt/i.test(scripts)) {
    if (/password|key\s*[:=]\s*['"]/i.test(scripts)) {
      issues.push({ title: 'Client-Side Encryption with Hardcoded Key', description: 'Client-side encryption library used with potentially hardcoded key.', severity: 'critical', recommendation: 'Never embed encryption keys in client-side code. Use server-side encryption.' });
    }
  }
  return issues;
}

function checkClientSideAuth() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/if\s*\(\s*(?:isAdmin|isLoggedIn|authenticated|authorized|user\.role)\s*(?:===?|!==?)\s*/i.test(scripts)) {
    issues.push({ title: 'Client-Side Authorization Check', description: 'Authorization/role checks performed in client-side JavaScript code.', severity: 'high', recommendation: 'Always enforce authorization server-side. Client-side checks are easily bypassed.' });
  }
  return issues;
}

function checkClientSideHashOnly() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/md5|sha1|sha256|sha512/i.test(scripts) && /password/i.test(scripts)) {
    if (!/bcrypt|argon2|scrypt|pbkdf2/i.test(scripts)) {
      issues.push({ title: 'Client-Side Password Hashing Only', description: 'Password hashing in client-side code without server-side rehashing.', severity: 'high', recommendation: 'Hash passwords server-side with bcrypt/argon2/scrypt. Client-side hashing alone is insufficient.' });
    }
  }
  return issues;
}

function checkClientSideValidation() {
  const issues = [];
  const forms = document.querySelectorAll('form');
  for (const f of forms) {
    const hasHTML5Validation = f.querySelector('[required], [pattern], [minlength], [maxlength]');
    if (hasHTML5Validation) {
      issues.push({ title: 'Client-Side Validation Detected', description: 'HTML5 validation attributes found. Ensure equivalent server-side validation exists.', severity: 'low', recommendation: 'Always duplicate client-side validation on the server. Client-side validation can be bypassed.' });
      break;
    }
  }
  return issues;
}

function checkClientTemplateInjection() {
  const issues = [];
  const body = document.body ? document.body.innerHTML : '';
  if (/\{\{.*\}\}/i.test(body) && !/ng-app|v-app|react|angular|vue/i.test(body)) {
    issues.push({ title: 'Client Template Injection Risk', description: 'Template expressions ({{ }}) detected outside known framework context.', severity: 'medium', recommendation: 'Ensure template expressions are properly escaped and not user-controllable.' });
  }
  return issues;
}

function checkClientValidationOnly() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const forms = document.querySelectorAll('form');
  if (forms.length > 0 && /validate|validation|isValid|checkForm/i.test(scripts)) {
    if (/return\s+false|preventDefault|event\.stop/i.test(scripts) && !/ajax|fetch|XMLHttp/i.test(scripts)) {
      issues.push({ title: 'Form Validation May Be Client-Side Only', description: 'Form validation appears to only prevent submission without server-side verification.', severity: 'medium', recommendation: 'Implement matching server-side validation for all form inputs.' });
    }
  }
  return issues;
}

function checkClipboardAPI() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/navigator\.clipboard|document\.execCommand\s*\(\s*['"]copy|clipboardData/i.test(scripts)) {
    issues.push({ title: 'Clipboard API Usage', description: 'Clipboard API access detected. Ensure no sensitive data is inadvertently copied.', severity: 'low', recommendation: 'Use Clipboard API responsibly. Clear clipboard data after use and inform users.' });
  }
  return issues;
}

function checkClipboardProtection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/password|token|secret|key/i.test(scripts) && /clipboard|copy|paste/i.test(scripts)) {
    if (!/clear|timeout|setTimeout.*clipboard/i.test(scripts)) {
      issues.push({ title: 'Clipboard Not Cleared After Copy', description: 'Sensitive data may remain in clipboard indefinitely.', severity: 'medium', recommendation: 'Clear clipboard after a short timeout when copying sensitive data.' });
    }
  }
  return issues;
}

function checkCloudBackup() { return []; }
function checkCloudMetadataSSRF() { return []; }
function checkCloudSQLPublic() { return []; }
function checkCloudTrail() { return []; }
function checkCodeReviewProcess() { return []; }
function checkCodeSigning() { return []; }

function checkCommandInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/exec\s*\(|spawn\s*\(|system\s*\(|popen\s*\(|shell_exec/i.test(scripts)) {
    issues.push({ title: 'Command Execution Call Detected', description: 'System/shell command execution functions found in code.', severity: 'critical', recommendation: 'Avoid command execution with user input. Use parameterized commands and input validation.' });
  }
  return issues;
}

function checkCommitSigning() { return []; }

function checkCommonPasswords() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/password\s*[:=]\s*['"](?:password|123456|admin|letmein|welcome|qwerty|abc123)/i.test(scripts)) {
    issues.push({ title: 'Common/Default Password in Code', description: 'Common or default password found hardcoded in JavaScript.', severity: 'critical', recommendation: 'Remove hardcoded passwords. Use environment variables and secrets management.' });
  }
  return issues;
}

function checkComposerJsonAccessible() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /composer\.json|composer\.lock/i.test(l))) {
    issues.push({ title: 'composer.json Publicly Accessible', description: 'PHP dependency file (composer.json/lock) linked on page.', severity: 'high', recommendation: 'Block access to composer.json and composer.lock from web server.' });
  }
  return issues;
}

function checkCompressionLeakage() {
  const issues = [];
  // BREACH-type check - server side
  return [];
}

function checkConcurrentRequests() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Promise\.all\s*\(\s*\[.*fetch|Promise\.allSettled/i.test(scripts)) {
    issues.push({ title: 'Concurrent API Requests', description: 'Multiple concurrent API requests detected. Ensure server handles concurrent requests safely.', severity: 'low', recommendation: 'Implement proper concurrency controls and rate limiting on the server.' });
  }
  return issues;
}

function checkConcurrentSessions() {
  const issues = [];
  // Server-side check advisory
  const cookies = document.cookie;
  if (/session|sid|auth/i.test(cookies)) {
    issues.push({ title: 'Concurrent Session Control Advisory', description: 'Session cookies detected. Ensure server limits concurrent sessions per user.', severity: 'low', recommendation: 'Limit concurrent sessions and notify users when a new session is created.' });
  }
  return issues;
}

function checkConfigAPI() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/config|\/settings|\/env|\/configuration/i.test(scripts)) {
    issues.push({ title: 'Configuration API Endpoint Referenced', description: 'Configuration/settings endpoint found in client code.', severity: 'medium', recommendation: 'Restrict configuration endpoints with authentication. Never expose sensitive config values.' });
  }
  return issues;
}

function checkConfigFileAccess() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  const configFiles = ['web.config', '.htaccess', 'config.php', 'settings.py', 'application.yml', 'application.properties', 'appsettings.json'];
  for (const c of configFiles) {
    if (links.some(l => l.includes(c))) {
      issues.push({ title: 'Configuration File Accessible', description: `Configuration file "${c}" linked on page.`, severity: 'critical', recommendation: 'Block access to configuration files from the web server.' });
      break;
    }
  }
  return issues;
}

function checkConfigFilesExposed() {
  return checkConfigFileAccess();
}

function checkConfigLogging() { return []; }

function checkConfigManagementExposed() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/ansible|puppet|chef|terraform|cloudformation/i.test(body)) {
    issues.push({ title: 'Config Management Tool References', description: 'Configuration management tool references found on page.', severity: 'medium', recommendation: 'Remove configuration management tool references from public pages.' });
  }
  return issues;
}

function checkConfigValidation() { return []; }

function checkConnectionStringInCode() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:mongodb|postgres|mysql|redis|amqp|jdbc):\/\/[^\s'"]+/i.test(scripts) || /Server\s*=.*Database\s*=/i.test(scripts)) {
    issues.push({ title: 'Database Connection String in Client Code', description: 'Database connection string found in JavaScript source.', severity: 'critical', recommendation: 'Never expose database connection strings in client-side code.' });
  }
  return issues;
}

function checkConsoleStatements() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const count = (scripts.match(/console\.(log|debug|info|warn|error|trace|dir)\s*\(/g) || []).length;
  if (count > 5) {
    issues.push({ title: 'Excessive Console Statements', description: `${count} console statements found in inline scripts. May leak debug info.`, severity: 'low', recommendation: 'Remove or disable console statements in production code.' });
  }
  return issues;
}

function checkContainerCapabilities() { return []; }
function checkContainerEscape() { return []; }
function checkContainerHealthChecks() { return []; }
function checkContainerReadOnly() { return []; }
function checkContainerResourceLimits() { return []; }
function checkContextBasedAccess() { return []; }
function checkCopyleftConflict() { return []; }

function checkCoreDumpFiles() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /core\.\d+|\.dmp$|crash\.log|hs_err_pid/i.test(l))) {
    issues.push({ title: 'Core Dump File Accessible', description: 'Link to core dump or crash file found on page.', severity: 'critical', recommendation: 'Remove core dump files from web-accessible directories immediately.' });
  }
  return issues;
}

function checkCorrelationID() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/correlation.id|X-Correlation-ID|X-Request-ID|trace.id/i.test(scripts)) {
    issues.push({ title: 'No Correlation ID in API Calls', description: 'API calls without correlation/trace IDs for request tracking.', severity: 'low', recommendation: 'Include correlation IDs in all API requests for debugging and audit trails.' });
  }
  return issues;
}

function checkCORSBypass() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/mode\s*:\s*['"]no-cors['"]|credentials\s*:\s*['"]same-origin['"]/i.test(scripts)) {
    issues.push({ title: 'CORS Bypass Attempt', description: 'CORS bypass patterns detected in fetch configuration.', severity: 'medium', recommendation: 'Configure CORS properly on the server instead of using bypass techniques.' });
  }
  return issues;
}

function checkCORSContentType() { return []; }

function checkCORSCredentialsMissing() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/fetch.*\/api\/|XMLHttpRequest.*\/api\//i.test(scripts)) {
    if (/credentials\s*:\s*['"]omit['"]/i.test(scripts)) {
      issues.push({ title: 'CORS Credentials Omitted', description: 'API requests explicitly omit credentials, which may cause auth failures.', severity: 'low', recommendation: 'Use credentials: "include" or "same-origin" when authentication is needed.' });
    }
  }
  return issues;
}

function checkCORSErrors() { return []; }
function checkCORSInconsistent() { return []; }

function checkCORSMissing() {
  const issues = [];
  // Covered by header-based CORS checks
  return issues;
}

function checkCORSOptions() { return []; }
function checkCORSPreflightCache() { return []; }

function checkCORSPrivateNetwork() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)/i.test(scripts)) {
    issues.push({ title: 'Private Network Access in Client Code', description: 'References to private/internal IP addresses found in client JavaScript.', severity: 'high', recommendation: 'Remove internal IP addresses from client-side code. Use a backend proxy.' });
  }
  return issues;
}

function checkCORSReflection() { return []; }
function checkCORSStatic() { return []; }
function checkCORSTiming() { return []; }

function checkCRCForSecurity() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/crc32|crc16|checksum.*security|integrity.*crc/i.test(scripts)) {
    issues.push({ title: 'CRC Used for Security', description: 'CRC (non-cryptographic checksum) used where cryptographic integrity is needed.', severity: 'high', recommendation: 'Use cryptographic hash functions (SHA-256) instead of CRC for security purposes.' });
  }
  return issues;
}

function checkCreditCardStorage() {
  const issues = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const val = localStorage.getItem(key) || '';
      if (/\d{13,19}/.test(val) && /card|credit|pan|payment/i.test(key)) {
        issues.push({ title: 'Credit Card Data in localStorage', description: 'Potential credit card numbers found stored in localStorage.', severity: 'critical', recommendation: 'Never store credit card data in localStorage. This violates PCI DSS.' });
        break;
      }
    }
  } catch (_) {}
  return issues;
}

function checkCrossdomainXml() {
  const issues = [];
  // Server-side check
  return [];
}

function checkCrossTabSession() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/BroadcastChannel|storage.*event|addEventListener.*storage/i.test(scripts)) {
    if (/session|token|auth/i.test(scripts)) {
      issues.push({ title: 'Cross-Tab Session Sharing', description: 'Session data shared between tabs via storage events or BroadcastChannel.', severity: 'medium', recommendation: 'Be cautious when sharing session data across tabs. Implement proper synchronization.' });
    }
  }
  return issues;
}

function checkCrossTenantAPI() { return []; }
function checkCrossTenantLeakage() { return []; }

function checkCSPNonceReuse() {
  const issues = [];
  const scripts = document.querySelectorAll('script[nonce]');
  const nonces = new Set();
  for (const s of scripts) {
    const n = s.getAttribute('nonce');
    if (n && nonces.has(n)) {
      issues.push({ title: 'CSP Nonce Reused', description: 'Same CSP nonce value used on multiple script elements.', severity: 'high', recommendation: 'Generate a unique nonce for each page load. Never reuse nonces.' });
      break;
    }
    if (n) nonces.add(n);
  }
  return issues;
}

function checkCSRFInGET() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]'));
  for (const a of links) {
    const href = a.href || '';
    if (/delete|remove|update|change|modify|transfer/i.test(href) && /[?&]/.test(href)) {
      issues.push({ title: 'State-Changing Action via GET', description: `Link with state-changing action uses GET: ${href.slice(0, 80)}`, severity: 'high', recommendation: 'Use POST/PUT/DELETE for state-changing actions, never GET with query parameters.' });
      break;
    }
  }
  return issues;
}

function checkCSRFReuse() {
  const issues = [];
  const tokens = document.querySelectorAll('input[name*="csrf"], input[name*="xsrf"], meta[name*="csrf"]');
  const values = new Set();
  for (const t of tokens) {
    const v = t.value || t.content || '';
    if (v && values.has(v)) {
      issues.push({ title: 'CSRF Token Reused Across Forms', description: 'Same CSRF token value found in multiple forms.', severity: 'medium', recommendation: 'Generate unique CSRF tokens per form or per request.' });
      break;
    }
    if (v) values.add(v);
  }
  return issues;
}

function checkCSRFSessionBinding() {
  const issues = [];
  const token = document.querySelector('input[name*="csrf"], meta[name*="csrf-token"]');
  if (token) {
    const val = token.value || token.content || '';
    if (val && val.length < 16) {
      issues.push({ title: 'CSRF Token Too Short', description: 'CSRF token appears too short for sufficient entropy.', severity: 'medium', recommendation: 'Use CSRF tokens of at least 128 bits (32 hex chars) bound to user session.' });
    }
  }
  return issues;
}

function checkCSRFToken() {
  const issues = [];
  const forms = document.querySelectorAll('form[method="post" i], form[method="POST"]');
  for (const f of forms) {
    const hasCsrf = f.querySelector('input[name*="csrf"], input[name*="xsrf"], input[name*="_token"], input[name*="authenticity_token"]');
    if (!hasCsrf) {
      const action = f.action || f.getAttribute('action') || '';
      issues.push({ title: 'POST Form Without CSRF Token', description: `POST form without CSRF token: ${action.slice(0, 80) || '(no action)'}`, severity: 'high', recommendation: 'Include CSRF tokens in all POST forms.' });
      break;
    }
  }
  return issues;
}

function checkCSRFValidation() {
  // Server-side check
  return [];
}

function checkCSSComments() {
  const issues = [];
  const styles = Array.from(document.querySelectorAll('style')).map(s => s.textContent).join('\n');
  if (/\/\*.*(?:TODO|FIXME|HACK|BUG|password|secret|key|token|internal)/i.test(styles)) {
    issues.push({ title: 'Sensitive Info in CSS Comments', description: 'CSS comments contain potentially sensitive information.', severity: 'low', recommendation: 'Remove sensitive comments from CSS in production builds.' });
  }
  return issues;
}

function checkCustomCrypto() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/function\s+(?:encrypt|decrypt|hash|cipher)|custom.*crypt|my.*encrypt/i.test(scripts)) {
    if (!/Web.*Crypto|crypto\.subtle|CryptoJS|sjcl|forge/i.test(scripts)) {
      issues.push({ title: 'Custom Cryptography Implementation', description: 'Custom encryption/hashing implementation detected instead of standard libraries.', severity: 'critical', recommendation: 'Use established cryptographic libraries (Web Crypto API, CryptoJS). Never roll your own crypto.' });
    }
  }
  return issues;
}

function checkCustomElements() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/customElements\.define/i.test(scripts)) {
    if (/innerHTML|insertAdjacentHTML|document\.write/i.test(scripts)) {
      issues.push({ title: 'Custom Elements with Unsafe HTML', description: 'Custom elements use innerHTML or similar unsafe HTML insertion.', severity: 'medium', recommendation: 'Use safe DOM APIs (textContent, createElement) in custom elements instead of innerHTML.' });
    }
  }
  return issues;
}

function checkCVVStorage() {
  const issues = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (/cvv|cvc|cvn|security.code/i.test(key || '')) {
        issues.push({ title: 'CVV/CVC Stored in Browser', description: 'Card verification value appears stored in localStorage.', severity: 'critical', recommendation: 'Never store CVV/CVC values. This is a PCI DSS violation.' });
        break;
      }
    }
  } catch (_) {}
  return issues;
}

function checkDangerousObjectMethods() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Object\.assign\s*\(\s*\{?\s*\}?\s*,.*(?:req\.body|req\.query|req\.params|user[Ii]nput|formData)/i.test(scripts)) {
    issues.push({ title: 'Dangerous Object Method with User Input', description: 'Object.assign or spread operator used with unsanitized user input, risking prototype pollution.', severity: 'high', recommendation: 'Validate and sanitize input before merging with objects. Use allowlists for permitted properties.' });
  }
  return issues;
}
