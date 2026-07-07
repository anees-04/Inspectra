// Batch 3: checkDanglingMarkup through checkGuestAccess

function checkDanglingMarkup() {
  const issues = [];
  const html = document.body ? document.body.innerHTML : '';
  if (/<[a-z]+\s+[^>]*=['"][^'"]*$/im.test(html.slice(0, 10000))) {
    issues.push({ title: 'Dangling Markup Detected', description: 'Unclosed HTML attribute found, which could enable dangling markup injection attacks.', severity: 'medium', recommendation: 'Ensure all HTML attributes are properly closed and user input is encoded.' });
  }
  return issues;
}

function checkDataAttributes() {
  const issues = [];
  const els = document.querySelectorAll('[data-user-id], [data-email], [data-token], [data-secret], [data-password], [data-api-key], [data-session], [data-role]');
  if (els.length > 0) {
    const attrs = Array.from(els).map(e => Array.from(e.attributes).filter(a => a.name.startsWith('data-') && /user|email|token|secret|pass|api|session|role/i.test(a.name)).map(a => a.name)).flat();
    issues.push({ title: 'Sensitive Data in HTML data-* Attributes', description: `Found ${els.length} element(s) with sensitive data attributes: ${[...new Set(attrs)].join(', ')}`, severity: 'medium', recommendation: 'Avoid storing sensitive data in HTML data attributes which are visible to any script.' });
  }
  return issues;
}

function checkDatabaseEncryption() { return []; }

function checkDatabaseErrors() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  const dbErrors = [/mysql.*error/i, /ORA-\d{5}/i, /SQLSTATE/i, /pg_query/i, /sqlite.*error/i, /mongodb.*error/i, /ODBC.*error/i, /DB2.*SQL/i];
  for (const p of dbErrors) {
    if (p.test(body)) {
      issues.push({ title: 'Database Error Message Exposed', description: 'Database error message visible on page, revealing database type and potentially query details.', severity: 'critical', recommendation: 'Catch database errors server-side and return generic error messages.' });
      break;
    }
  }
  return issues;
}

function checkDatabaseFilePath() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\.sqlite|\.db|\.mdb|\.accdb|\.sqlite3/i.test(body + scripts)) {
    issues.push({ title: 'Database File Path Exposed', description: 'Database file path or name found in page content or scripts.', severity: 'high', recommendation: 'Remove database file references from client-facing code.' });
  }
  return issues;
}

function checkDataClassification() { return []; }

function checkDataExportLimits() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/export|download.*csv|download.*xlsx|download.*json/i.test(scripts)) {
    if (!/limit|max|pagination/i.test(scripts)) {
      issues.push({ title: 'Data Export Without Limits', description: 'Data export functionality detected without visible size/count limits.', severity: 'medium', recommendation: 'Implement limits on data exports to prevent mass data extraction.' });
    }
  }
  return issues;
}

function checkDataMasking() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  // Check for unmasked credit cards, SSN, etc.
  if (/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/.test(body)) {
    issues.push({ title: 'Unmasked Credit Card Number', description: 'Full credit card number pattern found displayed on page.', severity: 'critical', recommendation: 'Mask credit card numbers, showing only last 4 digits (e.g., **** **** **** 1234).' });
  }
  if (/\b\d{3}-\d{2}-\d{4}\b/.test(body)) {
    issues.push({ title: 'Unmasked SSN Pattern', description: 'Social Security Number pattern found displayed on page.', severity: 'critical', recommendation: 'Mask SSNs, showing only last 4 digits (e.g., ***-**-1234).' });
  }
  return issues;
}

function checkDataMinimization() { return []; }
function checkDataRetention() { return []; }

function checkDBMonitorExposed() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/phpmyadmin|adminer|pgadmin|mongo.express|redis.commander|elasticsearch.head/i.test(body)) {
    issues.push({ title: 'Database Monitor Tool Exposed', description: 'Database management tool (phpMyAdmin, Adminer, pgAdmin, etc.) detected on page.', severity: 'critical', recommendation: 'Remove or restrict access to database management tools in production.' });
  }
  return issues;
}

function checkDebugEndpoints() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n').toLowerCase();
  const debugPaths = ['/debug', '/_debug', '/trace', '/profiler', '/actuator', '/metrics', '/dump', '/heapdump', '/env', '/beans', '/mappings'];
  for (const p of debugPaths) {
    if (links.some(l => l.includes(p)) || scripts.includes(p)) {
      issues.push({ title: 'Debug Endpoint Referenced', description: `Debug/diagnostic endpoint "${p}" found in page content.`, severity: 'high', recommendation: 'Disable debug endpoints in production. Restrict access with authentication.' });
      break;
    }
  }
  return issues;
}

function checkDebugErrorPage() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  if (/Django.*Debug|Werkzeug.*Debugger|Laravel.*Whoops|Yii.*Debug|Spring.*Whitelabel.*Error/i.test(body)) {
    issues.push({ title: 'Framework Debug Error Page', description: 'Framework debug error page detected in production.', severity: 'critical', recommendation: 'Disable debug mode in production. Set DEBUG=False and use custom error pages.' });
  }
  return issues;
}

function checkDebuggerStatement() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\bdebugger\b/i.test(scripts)) {
    issues.push({ title: 'Debugger Statement in Code', description: 'JavaScript "debugger" statement found in production code.', severity: 'medium', recommendation: 'Remove debugger statements from production code.' });
  }
  return issues;
}

function checkDebugMode() {
  const issues = [];
  const html = document.documentElement ? document.documentElement.innerHTML.slice(0, 15000) : '';
  if (/debug\s*[:=]\s*true|DEBUG\s*=\s*True|mode.*debug|isDebug/i.test(html)) {
    issues.push({ title: 'Debug Mode Enabled', description: 'Debug mode appears to be enabled in production.', severity: 'high', recommendation: 'Disable debug mode in production environments.' });
  }
  return issues;
}

function checkDebugToken() {
  const issues = [];
  const url = window.location.href;
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/[?&]debug=|[?&]test=true|[?&]_debug/i.test(url) || /debug.*token|debug.*key/i.test(scripts)) {
    issues.push({ title: 'Debug Token/Parameter Detected', description: 'Debug parameter or token found in URL or client code.', severity: 'medium', recommendation: 'Remove debug parameters and tokens from production URLs and code.' });
  }
  return issues;
}

function checkDefaultCredentials() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const defaults = [/admin.*admin/i, /root.*root/i, /test.*test/i, /user.*password/i, /guest.*guest/i, /demo.*demo/i];
  for (const p of defaults) {
    if (p.test(scripts)) {
      issues.push({ title: 'Default Credentials in Code', description: 'Default username/password combination found in JavaScript code.', severity: 'critical', recommendation: 'Remove all default credentials from client-side code.' });
      break;
    }
  }
  return issues;
}

function checkDefaultDeny() { return []; }

function checkDefaultKeys() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const defaultKeys = ['changeme', 'secret', 'your-secret-key', 'your-api-key', 'default-key', 'test-key', 'example-key', 'xxxxxxxx', '00000000'];
  for (const k of defaultKeys) {
    if (scripts.toLowerCase().includes(k)) {
      issues.push({ title: 'Default/Placeholder Key in Code', description: `Default or placeholder key "${k}" found in JavaScript.`, severity: 'critical', recommendation: 'Replace all default keys with unique, securely generated keys.' });
      break;
    }
  }
  return issues;
}

function checkDefaultPasswords() {
  return checkDefaultCredentials();
}

function checkDefaultPorts() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const ports = [':3306', ':5432', ':27017', ':6379', ':9200', ':5672', ':1433', ':1521', ':8080', ':8443'];
  for (const p of ports) {
    if (scripts.includes(p)) {
      issues.push({ title: 'Default Service Port in Client Code', description: `Default service port ${p} found in JavaScript, indicating direct service access.`, severity: 'medium', recommendation: 'Remove direct service port references from client code. Use API gateway or proxy.' });
      break;
    }
  }
  return issues;
}

function checkDefaultRolePermissions() { return []; }

function checkDeleteAuthorization() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/method\s*:\s*['"]DELETE|\.delete\s*\(/i.test(scripts) && !/confirm|authorization|role|permission/i.test(scripts)) {
    issues.push({ title: 'Delete Without Authorization Check', description: 'DELETE operations found without visible authorization verification.', severity: 'high', recommendation: 'Verify user authorization before allowing destructive operations.' });
  }
  return issues;
}

function checkDependencyAuditTrail() { return []; }
function checkDependencyConfusion() { return []; }
function checkDependencyConfusionRisk() { return []; }
function checkDependencyFirewall() { return []; }
function checkDependencyRollback() { return []; }
function checkDependencyScanning() { return []; }
function checkDependencyVisualization() { return []; }
function checkDeploymentApproval() { return []; }
function checkDeploymentGates() { return []; }
function checkDeprecatedPackages() { return []; }

function checkDES() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/DES\.|TripleDES|3DES|DES-CBC|DES-ECB/i.test(scripts)) {
    issues.push({ title: 'DES/3DES Encryption Detected', description: 'Weak DES or 3DES encryption algorithm found in code.', severity: 'high', recommendation: 'Replace DES/3DES with AES-256-GCM or ChaCha20-Poly1305.' });
  }
  return issues;
}

function checkDeserializationInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/JSON\.parse\s*\(.*(?:location|user|input|cookie|localStorage|sessionStorage)/i.test(scripts)) {
    issues.push({ title: 'Deserialization of Untrusted Data', description: 'JSON.parse used on potentially untrusted data without validation.', severity: 'medium', recommendation: 'Validate and sanitize data before JSON.parse. Use schemas for input validation.' });
  }
  return issues;
}

function checkDevDependenciesInProd() { return []; }
function checkDeveloperAccountSecurity() { return []; }

function checkDirectoryListing() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  const title = document.title || '';
  if (/Index of \/|Directory listing|Parent Directory|<dir>/i.test(body + ' ' + title)) {
    issues.push({ title: 'Directory Listing Enabled', description: 'Directory listing appears to be enabled on this server.', severity: 'high', recommendation: 'Disable directory listing in web server configuration.' });
  }
  return issues;
}

function checkDisabledSubmit() {
  const issues = [];
  const btns = document.querySelectorAll('button[disabled], input[type="submit"][disabled]');
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (btns.length > 0 && /disabled.*false|removeAttribute.*disabled/i.test(scripts)) {
    issues.push({ title: 'Client-Side Submit Gate', description: 'Submit button disabled/enabled by client-side logic, which can be bypassed.', severity: 'low', recommendation: 'Enforce submission validation server-side, not just by disabling buttons.' });
  }
  return issues;
}

function checkDisclosureProcess() { return []; }

function checkDiscountValidation() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/discount|coupon|promo|voucher/i.test(scripts) && /apply|validate|calculate/i.test(scripts)) {
    if (/\.value|parseInt|parseFloat/i.test(scripts)) {
      issues.push({ title: 'Client-Side Discount Validation', description: 'Discount/coupon validation logic found in client-side JavaScript.', severity: 'high', recommendation: 'Validate all discounts and coupons exclusively on the server.' });
    }
  }
  return issues;
}

function checkDistributedRateLimit() { return []; }
function checkDistributedTracing() { return []; }

function checkDjangoDebugToolbar() {
  const issues = [];
  if (document.querySelector('#djdt, .djdt, [data-djdt], #djDebug')) {
    issues.push({ title: 'Django Debug Toolbar Active', description: 'Django Debug Toolbar is visible in production, exposing SQL queries and request data.', severity: 'critical', recommendation: 'Disable Django Debug Toolbar in production (set DEBUG=False).' });
  }
  return issues;
}

function checkDLP() { return []; }

function checkDNSRebinding() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(scripts) && /fetch|XMLHttp|ajax/i.test(scripts)) {
    issues.push({ title: 'DNS Rebinding Risk', description: 'Client code makes requests to localhost/loopback, which could be exploited via DNS rebinding.', severity: 'medium', recommendation: 'Validate Host header server-side. Avoid hardcoding localhost in client code.' });
  }
  return issues;
}

function checkDockerFilesAccessible() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /dockerfile|docker-compose|\.dockerignore/i.test(l))) {
    issues.push({ title: 'Docker Files Publicly Accessible', description: 'Docker configuration files linked on page.', severity: 'high', recommendation: 'Block access to Docker files from the web server.' });
  }
  return issues;
}

function checkDockerRoot() { return []; }
function checkDockerSocketMount() { return []; }

function checkDocumentWrite() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/document\.write\s*\(|document\.writeln\s*\(/i.test(scripts)) {
    issues.push({ title: 'document.write() Usage', description: 'document.write() found in code, which is a DOM XSS sink.', severity: 'medium', recommendation: 'Replace document.write() with safer DOM manipulation methods (createElement, textContent).' });
  }
  return issues;
}

function checkDOMClobbering() {
  const issues = [];
  const ids = Array.from(document.querySelectorAll('[id]')).map(e => e.id);
  const dangerous = ['location', 'document', 'window', 'self', 'top', 'parent', 'frames', 'opener', 'closed', 'length'];
  const clobbered = ids.filter(id => dangerous.includes(id.toLowerCase()));
  if (clobbered.length > 0) {
    issues.push({ title: 'DOM Clobbering Risk', description: `Element IDs shadow global properties: ${clobbered.join(', ')}`, severity: 'high', recommendation: 'Avoid using global property names as element IDs. This enables DOM clobbering attacks.' });
  }
  return issues;
}

function checkDOMXSS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const sinks = ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML', 'eval(', 'setTimeout(', 'setInterval(', 'Function('];
  const sources = ['location.hash', 'location.search', 'location.href', 'document.referrer', 'document.URL', 'document.cookie', 'window.name', 'postMessage'];
  let hasSink = false, hasSource = false;
  for (const sink of sinks) { if (scripts.includes(sink)) { hasSink = true; break; } }
  for (const src of sources) { if (scripts.includes(src)) { hasSource = true; break; } }
  if (hasSink && hasSource) {
    issues.push({ title: 'Potential DOM XSS', description: 'Both DOM XSS sources (user input) and sinks (dangerous output) found in same code.', severity: 'high', recommendation: 'Sanitize all user-controlled data before passing to DOM sinks. Use textContent instead of innerHTML.' });
  }
  return issues;
}

function checkDownloadAnomalies() { return []; }
function checkDuplicateDependencies() { return []; }

function checkDynamicImport() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/import\s*\(.*(?:location|user|input|param|query|hash)/i.test(scripts)) {
    issues.push({ title: 'Dynamic Import with User Input', description: 'Dynamic import() using user-controlled input, risking code injection.', severity: 'high', recommendation: 'Never use user input in dynamic import() paths. Use a fixed allowlist of modules.' });
  }
  return issues;
}

function checkECBMode() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/ECB|mode\s*:\s*CryptoJS\.mode\.ECB|aes-\d+-ecb/i.test(scripts)) {
    issues.push({ title: 'ECB Encryption Mode Detected', description: 'ECB mode encryption detected. ECB does not provide semantic security.', severity: 'high', recommendation: 'Use CBC, GCM, or CTR mode instead of ECB. ECB reveals patterns in encrypted data.' });
  }
  return issues;
}

function checkELInjection() { return []; }
function checkEmailEncryption() { return []; }

function checkEmailEnumeration() {
  const issues = [];
  const forms = document.querySelectorAll('form');
  for (const f of forms) {
    if (/forgot|reset|recover/i.test((f.action || '') + (f.id || '') + (f.className || ''))) {
      issues.push({ title: 'Email Enumeration via Password Reset', description: 'Password reset form detected. Ensure it does not reveal if an email exists.', severity: 'medium', recommendation: 'Always respond with "If this email exists, a reset link was sent" regardless of email validity.' });
      break;
    }
  }
  return issues;
}

function checkEmailInHTML() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 10000) : '';
  const emails = body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
  if (emails && emails.length > 0) {
    const unique = [...new Set(emails)];
    if (unique.length > 0) {
      issues.push({ title: 'Email Addresses Exposed in Page', description: `${unique.length} email address(es) found in page content, vulnerable to scraping.`, severity: 'low', recommendation: 'Obfuscate email addresses in HTML to prevent scraping by bots.' });
    }
  }
  return issues;
}

function checkEmailValidation() {
  const issues = [];
  const emailInputs = document.querySelectorAll('input[type="email"], input[name*="email"]');
  for (const i of emailInputs) {
    if (i.type !== 'email' && !i.pattern) {
      issues.push({ title: 'Email Input Without Validation', description: 'Email input field lacks type="email" or pattern attribute for basic validation.', severity: 'low', recommendation: 'Use type="email" and server-side validation for email inputs.' });
      break;
    }
  }
  return issues;
}

function checkEncryptionAtRest() { return []; }

function checkEnvFileExposed() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (links.some(l => /\.env($|\?|#)/i.test(l)) || /DB_PASSWORD|APP_KEY|SECRET_KEY|AWS_SECRET/i.test(body)) {
    issues.push({ title: '.env File Exposed or Env Vars Visible', description: 'Environment file or environment variable values found on page.', severity: 'critical', recommendation: 'Block .env file access via web server. Never display env vars in client-facing pages.' });
  }
  return issues;
}

function checkEnvInfoInClient() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/process\.env|NODE_ENV|REACT_APP_|NEXT_PUBLIC_|VITE_/i.test(scripts)) {
    if (/SECRET|PASSWORD|KEY|TOKEN|DATABASE/i.test(scripts)) {
      issues.push({ title: 'Sensitive Environment Info in Client', description: 'Environment variables with sensitive names found in client-side JavaScript.', severity: 'high', recommendation: 'Only expose non-sensitive env vars (prefixed NEXT_PUBLIC_, VITE_, etc.) to the client.' });
    }
  }
  return issues;
}

function checkEnvInjection() { return []; }

function checkEnvironmentDetection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/development|staging|test.*environment|localhost.*env/i.test(scripts)) {
    issues.push({ title: 'Environment Detection in Client Code', description: 'Environment-specific code (development/staging) found in production JavaScript.', severity: 'medium', recommendation: 'Remove environment detection code from production builds. Use build-time constants.' });
  }
  return issues;
}

function checkErrorMessageXSS() {
  const issues = [];
  const url = window.location.href;
  const params = new URLSearchParams(window.location.search);
  const body = document.body ? document.body.innerHTML : '';
  for (const [, value] of params) {
    if (value.length > 3 && body.includes(value) && /<|>|&lt;|&gt;/.test(value)) {
      issues.push({ title: 'Error Message Reflects User Input', description: 'User input from URL parameters appears reflected in page content without encoding.', severity: 'high', recommendation: 'Encode all user input before rendering in error messages.' });
      break;
    }
  }
  return issues;
}

function checkErrorTrackingLeakage() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/Sentry\.init|Bugsnag\.start|Rollbar\.init|TrackJS|window\.onerror.*report/i.test(scripts)) {
    if (/dsn\s*[:=]|apiKey\s*[:=]|token\s*[:=]/i.test(scripts)) {
      issues.push({ title: 'Error Tracking API Key Exposed', description: 'Error tracking service configuration with API keys found in client code.', severity: 'medium', recommendation: 'Use public-facing DSNs/keys only. Ensure error reports don\'t contain PII.' });
    }
  }
  return issues;
}

function checkETagInodes() { return []; }

function checkEvalUsage() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\beval\s*\(/i.test(scripts)) {
    issues.push({ title: 'eval() Usage Detected', description: 'JavaScript eval() function found in code, enabling arbitrary code execution.', severity: 'high', recommendation: 'Remove eval() usage. Use JSON.parse for data, and avoid dynamic code execution.' });
  }
  return issues;
}

function checkEventSourceEncryption() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/new\s+EventSource\s*\(/i.test(scripts)) {
    if (/http:\/\//i.test(scripts)) {
      issues.push({ title: 'EventSource Over HTTP', description: 'Server-Sent Events (SSE) connection over unencrypted HTTP.', severity: 'high', recommendation: 'Use HTTPS for all SSE/EventSource connections.' });
    }
  }
  return issues;
}

function checkEventSourcingAudit() { return []; }

function checkExcessiveAPIData() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\/.*\*|fields=\*|select.*\*/i.test(scripts)) {
    issues.push({ title: 'Excessive API Data Exposure', description: 'API calls requesting all fields/data detected (wildcard selection).', severity: 'medium', recommendation: 'Request only needed fields from APIs. Implement field-level filtering server-side.' });
  }
  return issues;
}

function checkExcessiveDataExposure() {
  return checkExcessiveAPIData();
}

function checkExcessiveDependencies() { return []; }

function checkExcessiveLogging() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const logCount = (scripts.match(/console\.\w+\s*\(/g) || []).length;
  if (logCount > 20) {
    issues.push({ title: 'Excessive Client-Side Logging', description: `${logCount} console logging statements found. May leak debug information.`, severity: 'medium', recommendation: 'Remove excessive logging in production. Use a logging library with level control.' });
  }
  return issues;
}

function checkExpiredCert() { return []; }

function checkFailedLoginLogging() { return []; }

function checkFastHashPasswords() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:md5|sha1|sha256)\s*\(.*password/i.test(scripts)) {
    issues.push({ title: 'Fast Hash Used for Passwords', description: 'Fast hash function (MD5/SHA) used for password hashing instead of slow KDF.', severity: 'critical', recommendation: 'Use bcrypt, Argon2, or scrypt for password hashing. Fast hashes are trivially crackable.' });
  }
  return issues;
}

function checkFeatureFlags() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/featureFlag|feature_flag|isEnabled|toggleFeature|unleash|launchdarkly/i.test(scripts)) {
    if (/admin|internal|beta|experimental|debug/i.test(scripts)) {
      issues.push({ title: 'Feature Flags Expose Internal Features', description: 'Feature flag logic in client code may expose internal/debug features.', severity: 'medium', recommendation: 'Evaluate feature flags server-side. Don\'t ship disabled feature code to clients.' });
    }
  }
  return issues;
}

function checkFileCommandInjection() {
  return checkCommandInjection();
}

function checkFileDownloadAuth() { return []; }
function checkFileExtensionOnly() { return []; }
function checkFileInclusion() { return []; }
function checkFileIntegrityHash() { return []; }
function checkFileLocking() { return []; }

function checkFilePathInErrors() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 10000) : '';
  if (/[A-Z]:\\[\w\\]+\.\w+|\/(?:home|var|usr|opt|srv)\/[\w\/]+\.\w+/i.test(body)) {
    issues.push({ title: 'File Path Exposed in Error', description: 'Server file system path found in page content.', severity: 'high', recommendation: 'Sanitize error messages to remove server file paths.' });
  }
  return issues;
}

function checkFilePermissions() { return []; }
function checkFileProtocolSSRF() { return []; }

// Note: the DB has a space in this name "checkFileSize Limit" - register both
function checkFileSizeLimit() {
  const issues = [];
  const fileInputs = document.querySelectorAll('input[type="file"]');
  for (const i of fileInputs) {
    if (!i.getAttribute('accept')) {
      issues.push({ title: 'File Upload Without Type Restriction', description: 'File input without accept attribute allows any file type.', severity: 'medium', recommendation: 'Restrict file types with accept attribute and validate server-side.' });
      break;
    }
  }
  return issues;
}
// Create the space-named alias
globalThis['checkFileSize Limit'] = checkFileSizeLimit;

function checkFileTypeWhitelist() {
  return checkFileSizeLimit();
}

function checkFileUploadAuth() { return []; }

function checkFileUploadRCE() {
  const issues = [];
  const fileInputs = document.querySelectorAll('input[type="file"]');
  if (fileInputs.length > 0) {
    const accept = Array.from(fileInputs).map(i => i.getAttribute('accept') || '').join(',');
    if (!accept || /\.\*|\.php|\.jsp|\.asp|\.exe|\.sh|\.bat|\.cmd|\.py|\.rb|\.pl/i.test(accept)) {
      issues.push({ title: 'File Upload RCE Risk', description: 'File upload allows potentially executable file types.', severity: 'critical', recommendation: 'Restrict uploads to safe file types. Validate MIME type and content server-side. Store outside web root.' });
    }
  }
  return issues;
}

function checkFileUploadValidation() {
  const issues = [];
  const fileInputs = document.querySelectorAll('input[type="file"]');
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (fileInputs.length > 0 && !/fileSize|maxSize|validateFile|file.*validation/i.test(scripts)) {
    issues.push({ title: 'File Upload Without Validation', description: 'File upload inputs found without visible client-side validation.', severity: 'medium', recommendation: 'Validate file type, size, and content both client-side and server-side.' });
  }
  return issues;
}

function checkFontCORS() {
  const issues = [];
  const fonts = document.querySelectorAll('link[rel="stylesheet"][href*="fonts"], link[href*="font"]');
  for (const f of fonts) {
    if (f.href && !f.crossOrigin && /cdn|fonts\.googleapis|fonts\.gstatic/i.test(f.href)) {
      issues.push({ title: 'Font Resource Missing crossorigin', description: 'Cross-origin font loaded without crossorigin attribute.', severity: 'low', recommendation: 'Add crossorigin="anonymous" to cross-origin font resources.' });
      break;
    }
  }
  return issues;
}

function checkFontsHTTP() {
  const issues = [];
  const fonts = document.querySelectorAll('link[href^="http:"][rel*="stylesheet"], style');
  for (const f of fonts) {
    const href = f.href || f.textContent || '';
    if (/http:\/\/.*font|http:\/\/.*woff/i.test(href)) {
      issues.push({ title: 'Fonts Loaded Over HTTP', description: 'Font resources loaded over unencrypted HTTP connection.', severity: 'medium', recommendation: 'Load all font resources over HTTPS.' });
      break;
    }
  }
  return issues;
}

function checkForcedBrowsing() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 3000).toLowerCase() : '';
  if (/forbidden|403|unauthorized|401|access denied/i.test(body)) {
    issues.push({ title: 'Forced Browsing Indicators', description: 'Access denied messages suggest forced browsing attempts may reach restricted resources.', severity: 'low', recommendation: 'Return consistent 404 for non-existent and forbidden resources to avoid path enumeration.' });
  }
  return issues;
}

function checkForkDispute() { return []; }
function checkFREAK() { return []; }
function checkFrequentBreaking() { return []; }

function checkFunctionConstructor() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/new\s+Function\s*\(/i.test(scripts)) {
    issues.push({ title: 'Function Constructor Usage', description: 'new Function() constructor used, which is similar to eval() and enables code injection.', severity: 'high', recommendation: 'Avoid new Function() constructor. Use safer alternatives for dynamic behavior.' });
  }
  return issues;
}

function checkFunctionLevelAuth() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/admin\/|\/manage\/|\/internal\//i.test(scripts)) {
    if (!/authorization|auth.*check|role.*check|permission.*check/i.test(scripts)) {
      issues.push({ title: 'Function-Level Authorization Missing', description: 'Admin/internal API paths called without visible authorization checks.', severity: 'high', recommendation: 'Implement authorization checks at every function/endpoint level, not just at the API gateway.' });
    }
  }
  return issues;
}

function checkGatewayAdminExposed() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/kong.*admin|tyk.*dashboard|apigee|aws.*api.*gateway.*console/i.test(body)) {
    issues.push({ title: 'API Gateway Admin Interface Exposed', description: 'API gateway administration interface detected on page.', severity: 'critical', recommendation: 'Restrict API gateway admin access to internal networks with authentication.' });
  }
  return issues;
}

function checkGatewayCachingSensitive() { return []; }
function checkGatewayDDoSProtection() { return []; }
function checkGatewayHeaderInjection() { return []; }
function checkGatewayLogging() { return []; }
function checkGatewayMetrics() { return []; }
function checkGatewayMockResponses() { return []; }
function checkGatewayRateLimitMethod() { return []; }
function checkGatewayRequestSmuggling() { return []; }
function checkGatewaySSL() { return []; }
function checkGatewayTransformation() { return []; }
function checkGatewayValidation() { return []; }
function checkGatewayWAF() { return []; }

function checkGemfileAccessible() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /gemfile|gemfile\.lock/i.test(l))) {
    issues.push({ title: 'Gemfile Publicly Accessible', description: 'Ruby Gemfile linked on page, exposing dependency information.', severity: 'high', recommendation: 'Block access to Gemfile and Gemfile.lock from web server.' });
  }
  return issues;
}

function checkGitDependencies() { return []; }

function checkGitDirectoryAccess() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  if (links.some(l => /\.git\/|\.git$|\.gitignore|\.gitmodules/i.test(l))) {
    issues.push({ title: '.git Directory/Files Accessible', description: 'Git repository files found linked on page.', severity: 'critical', recommendation: 'Block access to .git directory and git files from the web server.' });
  }
  return issues;
}

function checkGitExposed() { return checkGitDirectoryAccess(); }
function checkGitignoreExposed() { return checkGitDirectoryAccess(); }
function checkGlobalAdminAccess() { return []; }
function checkGopherSSRF() { return []; }

function checkGraphQLAliases() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/graphql/i.test(scripts) && /alias.*:/i.test(scripts)) {
    issues.push({ title: 'GraphQL Alias Abuse Risk', description: 'GraphQL aliases used which can be used for batching attacks.', severity: 'medium', recommendation: 'Limit the number of aliases allowed per query.' });
  }
  return issues;
}

function checkGraphQLBatch() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/graphql/i.test(scripts) && /\[\s*\{.*query/i.test(scripts)) {
    issues.push({ title: 'GraphQL Batching Enabled', description: 'GraphQL batch queries detected. Can be abused for brute force attacks.', severity: 'medium', recommendation: 'Limit or disable GraphQL query batching. Set maximum batch size.' });
  }
  return issues;
}

function checkGraphQLCaching() { return []; }

function checkGraphQLCircular() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/graphql/i.test(scripts)) {
    issues.push({ title: 'GraphQL Circular Query Advisory', description: 'GraphQL endpoint detected. Ensure circular query prevention is implemented.', severity: 'low', recommendation: 'Implement query depth limiting and circular reference detection.' });
  }
  return issues;
}

function checkGraphQLComplexity() {
  return checkGraphQLCircular();
}

function checkGraphQLDataExposure() { return []; }
function checkGraphQLDataLoader() { return []; }

function checkGraphQLDepth() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/graphql/i.test(scripts)) {
    const nested = (scripts.match(/\{[^}]*\{[^}]*\{[^}]*\{/g) || []).length;
    if (nested > 0) {
      issues.push({ title: 'Deep GraphQL Query Nesting', description: 'Deeply nested GraphQL queries detected, risking DoS attacks.', severity: 'medium', recommendation: 'Implement depth limiting on GraphQL queries (recommended max depth: 5-10).' });
    }
  }
  return issues;
}

function checkGraphQLFieldAuth() { return []; }
function checkGraphQLFileUpload() { return []; }

function checkGraphQLInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/graphql/i.test(scripts) && /\$\{.*(?:input|user|param|query)/i.test(scripts)) {
    issues.push({ title: 'GraphQL Injection Risk', description: 'GraphQL queries built with string interpolation using user input.', severity: 'high', recommendation: 'Use GraphQL variables for user input. Never concatenate user data into queries.' });
  }
  return issues;
}

function checkGraphQLInputValidation() { return []; }

function checkGraphQLIntrospection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const body = document.body ? document.body.innerHTML.slice(0, 10000) : '';
  if (/__schema|__type|IntrospectionQuery/i.test(scripts + body)) {
    issues.push({ title: 'GraphQL Introspection Enabled', description: 'GraphQL introspection queries detected, exposing full API schema.', severity: 'high', recommendation: 'Disable GraphQL introspection in production environments.' });
  }
  return issues;
}

function checkGraphQLIntrospectionProd() {
  return checkGraphQLIntrospection();
}

function checkGraphQLMutationChain() { return []; }
function checkGraphQLMutationRate() { return []; }

function checkGraphQLPlayground() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/graphiql|graphql.*playground|graphql.*explorer|altair/i.test(body)) {
    issues.push({ title: 'GraphQL Playground/Explorer Exposed', description: 'GraphQL development playground detected in production.', severity: 'high', recommendation: 'Disable GraphQL playground and IDE tools in production.' });
  }
  return issues;
}

function checkGraphQLResolverErrors() { return []; }
function checkGraphQLSchemaStitching() { return []; }

function checkGraphQLSubscriptions() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/graphql.*subscription|ws:\/\/.*graphql/i.test(scripts)) {
    issues.push({ title: 'GraphQL Subscriptions (WebSocket)', description: 'GraphQL subscriptions via WebSocket detected. Ensure proper auth on subscriptions.', severity: 'medium', recommendation: 'Implement authentication and authorization on GraphQL subscriptions.' });
  }
  return issues;
}

function checkGraphQLTimeout() { return []; }

function checkGraphQLTracing() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000) : '';
  if (/tracing.*startTime|apollo.*tracing|extensions.*tracing/i.test(body)) {
    issues.push({ title: 'GraphQL Tracing Enabled', description: 'GraphQL tracing/performance data exposed in responses.', severity: 'medium', recommendation: 'Disable GraphQL tracing in production. It reveals resolver timing information.' });
  }
  return issues;
}

function checkGraphQLWhitelist() { return []; }
function checkGroupMembership() { return []; }

function checkGRPCTLS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/grpc|grpc-web/i.test(scripts) && /http:\/\//i.test(scripts)) {
    issues.push({ title: 'gRPC Without TLS', description: 'gRPC communication without TLS encryption detected.', severity: 'high', recommendation: 'Always use TLS for gRPC connections.' });
  }
  return issues;
}

function checkGuardDuty() { return []; }

function checkGuestAccess() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000).toLowerCase() : '';
  if (/guest.*access|anonymous.*access|continue.*guest|skip.*login/i.test(body)) {
    issues.push({ title: 'Guest/Anonymous Access Available', description: 'Guest or anonymous access option detected.', severity: 'low', recommendation: 'Limit guest access capabilities. Require authentication for sensitive operations.' });
  }
  return issues;
}
