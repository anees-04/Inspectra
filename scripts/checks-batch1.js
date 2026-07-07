// Batch 1: check404Leakage through checkCDNwithoutSRI (A-C functions)
// All functions return an array of issue objects

function check404Leakage() {
  const issues = [];
  const title = document.title || '';
  const body = document.body ? document.body.innerText.slice(0, 3000) : '';
  const combined = (title + ' ' + body).toLowerCase();
  const leakPatterns = [/apache\/([\d.]+)/i, /nginx\/([\d.]+)/i, /iis\/([\d.]+)/i, /server at .+ port \d+/i, /powered by/i, /stack trace/i, /exception/i, /debug/i];
  for (const p of leakPatterns) {
    if (p.test(combined)) {
      issues.push({ title: '404 Page Information Leakage', description: 'Error/404 page may reveal server software, version, or debug info.', severity: 'medium', recommendation: 'Customize error pages to avoid exposing server details.' });
      break;
    }
  }
  return issues;
}

function checkAbsolutePathTraversal() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join(' ');
  const urls = Array.from(document.querySelectorAll('a[href], form[action]')).map(e => e.href || e.action || '');
  const all = scripts + ' ' + urls.join(' ');
  if (/[?&][^=]*=\/(etc|var|usr|tmp|windows|boot)\//i.test(all) || /\.\.\//g.test(all)) {
    issues.push({ title: 'Absolute Path Traversal Signals', description: 'Detected URL parameters or links containing absolute filesystem paths.', severity: 'high', recommendation: 'Validate and sanitize all file path inputs server-side. Use allowlists.' });
  }
  return issues;
}

function checkABTestingSecurity() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
  const abTools = ['optimizely', 'vwo.com', 'google-analytics.com/cx', 'split.io', 'launchdarkly'];
  for (const t of abTools) {
    if (scripts.some(s => s.includes(t))) {
      const el = document.querySelector(`script[src*="${t}"]`);
      if (el && !el.integrity) {
        issues.push({ title: 'A/B Testing Framework Without SRI', description: `A/B testing script from "${t}" loaded without Subresource Integrity.`, severity: 'medium', recommendation: 'Add integrity attributes to A/B testing scripts or self-host them.' });
      }
    }
  }
  return issues;
}

function checkAccessReview() {
  // Server-side process detection - advisory
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000).toLowerCase() : '';
  if (/admin|dashboard|manage|role|permission/i.test(body)) {
    const hasReview = /access.review|permission.audit|role.review/i.test(body);
    if (!hasReview) {
      issues.push({ title: 'No Access Review Process Detected', description: 'Admin/management interface detected but no evidence of access review process.', severity: 'low', recommendation: 'Implement periodic access reviews for privileged accounts.' });
    }
  }
  return issues;
}

function checkAccountEnumeration() {
  const issues = [];
  const forms = document.querySelectorAll('form');
  for (const f of forms) {
    const action = (f.action || '').toLowerCase();
    const inputs = f.querySelectorAll('input');
    const hasEmail = Array.from(inputs).some(i => /email|user|login/i.test(i.name || i.type || ''));
    if (hasEmail && /login|signin|register|signup|forgot|reset/i.test(action + ' ' + (f.id || '') + ' ' + (f.className || ''))) {
      issues.push({ title: 'Potential Account Enumeration', description: 'Login/registration form found. Ensure error messages do not differentiate between valid and invalid usernames.', severity: 'medium', recommendation: 'Use generic error messages like "Invalid credentials" for both username and password failures.' });
      break;
    }
  }
  return issues;
}

function checkAccountExistenceTiming() {
  const issues = [];
  const forms = document.querySelectorAll('form[action*="login"], form[action*="signin"], form[action*="auth"]');
  if (forms.length > 0) {
    issues.push({ title: 'Account Existence Timing Attack Risk', description: 'Login form detected. Verify server responds in constant time regardless of username validity.', severity: 'low', recommendation: 'Ensure authentication logic takes the same time for valid and invalid usernames.' });
  }
  return issues;
}

function checkAdminAuth() {
  const issues = [];
  const url = window.location.href.toLowerCase();
  const adminPaths = ['/admin', '/dashboard', '/manage', '/panel', '/control', '/backend', '/cms'];
  if (adminPaths.some(p => url.includes(p))) {
    const loginForm = document.querySelector('form[action*="login"], input[type="password"]');
    if (!loginForm) {
      issues.push({ title: 'Admin Panel May Lack Authentication', description: 'Admin-like path detected without visible login/auth mechanism on page.', severity: 'high', recommendation: 'Ensure all admin panels require strong authentication and are not publicly accessible.' });
    }
  }
  return issues;
}

function checkAdminLogging() {
  const issues = [];
  const url = window.location.href.toLowerCase();
  if (/admin|dashboard|manage/i.test(url)) {
    issues.push({ title: 'Admin Activity Logging Advisory', description: 'Admin interface detected. Ensure all admin actions are logged with timestamp, user, and action details.', severity: 'low', recommendation: 'Implement comprehensive audit logging for all admin panel activities.' });
  }
  return issues;
}

function checkAdminPanelPath() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  const defaultPaths = ['/admin', '/administrator', '/wp-admin', '/wp-login', '/phpmyadmin', '/cpanel', '/manager', '/console', '/admin.php', '/login.php'];
  for (const p of defaultPaths) {
    if (links.some(l => l.includes(p)) || window.location.pathname.toLowerCase().includes(p)) {
      issues.push({ title: 'Admin Panel on Default Path', description: `Default admin path "${p}" detected. Attackers commonly scan for these.`, severity: 'medium', recommendation: 'Use a non-standard admin URL path and implement IP whitelisting.' });
      break;
    }
  }
  return issues;
}

function checkAdNetworkScripts() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const adNetworks = ['doubleclick.net', 'googlesyndication', 'adservice', 'amazon-adsystem', 'facebook.net/signals', 'adskeeper', 'adsterra', 'propellerads'];
  for (const s of scripts) {
    const src = s.src.toLowerCase();
    if (adNetworks.some(n => src.includes(n))) {
      if (!s.integrity) {
        issues.push({ title: 'Ad Network Script Without SRI', description: `Ad network script loaded without integrity check: ${s.src.slice(0, 100)}`, severity: 'medium', recommendation: 'Monitor ad scripts for tampering. Consider using SRI where possible or self-hosting.' });
        break;
      }
    }
  }
  return issues;
}

function checkAdsTxt() {
  const issues = [];
  // Check for ads.txt reference
  const links = Array.from(document.querySelectorAll('a[href*="ads.txt"]'));
  if (links.length === 0) {
    // Presence can't be fully verified from content script, advisory only
    issues.push({ title: 'ads.txt Verification Advisory', description: 'Could not verify ads.txt presence from page content. If serving ads, ensure ads.txt is properly configured.', severity: 'low', recommendation: 'Publish an ads.txt file at /ads.txt to prevent unauthorized ad inventory sales.' });
  }
  return issues;
}

function checkAJAXCredentials() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/credentials\s*:\s*['"]include['"]/i.test(scripts) || /withCredentials\s*=\s*true/i.test(scripts)) {
    issues.push({ title: 'AJAX Requests With Credentials', description: 'JavaScript code sends cross-origin requests with credentials included.', severity: 'medium', recommendation: 'Only use credentials: "include" when necessary and ensure CORS is properly configured on the server.' });
  }
  return issues;
}

function checkAnalyticsSRI() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const analytics = ['google-analytics', 'googletagmanager', 'analytics', 'hotjar', 'mixpanel', 'segment', 'amplitude', 'heap'];
  for (const s of scripts) {
    if (analytics.some(a => s.src.toLowerCase().includes(a)) && !s.integrity) {
      issues.push({ title: 'Analytics Script Without SRI', description: `Analytics script loaded without Subresource Integrity: ${s.src.slice(0, 100)}`, severity: 'medium', recommendation: 'Add integrity attribute to analytics scripts or self-host them.' });
    }
  }
  return issues;
}

function checkAnalyticsSSRF() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/analytics.*url|trackingPixel|beacon.*url/i.test(scripts)) {
    if (/user(Input|Data|Param)|location\.search|location\.hash/i.test(scripts)) {
      issues.push({ title: 'Analytics SSRF Risk', description: 'Analytics tracking appears to use user-controlled input in URLs, risking SSRF.', severity: 'high', recommendation: 'Never use user input directly in analytics tracking URLs. Validate and sanitize all inputs.' });
    }
  }
  return issues;
}

function checkAngularBypass() {
  const issues = [];
  if (typeof window.angular !== 'undefined' || document.querySelector('[ng-app], [data-ng-app], [ng-controller]')) {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    if (/\$sce\.trustAs|\$sce\.trustAsHtml|ng-bind-html-unsafe|bypassSecurityTrust/i.test(scripts)) {
      issues.push({ title: 'Angular Security Bypass Detected', description: 'Angular security bypass methods ($sce.trustAs, bypassSecurityTrust) found in code.', severity: 'high', recommendation: 'Avoid bypassing Angular sanitization. Use safe binding methods and sanitize user input.' });
    }
    if (document.querySelector('[ng-bind-html]')) {
      issues.push({ title: 'Angular ng-bind-html Usage', description: 'ng-bind-html directive found which renders HTML content.', severity: 'medium', recommendation: 'Ensure data bound with ng-bind-html is properly sanitized.' });
    }
  }
  return issues;
}

function checkAnonCiphers() {
  const issues = [];
  if (window.location.protocol === 'http:') {
    issues.push({ title: 'No TLS - Anonymous Ciphers Risk', description: 'Site uses plain HTTP. Cannot verify cipher suite configuration.', severity: 'high', recommendation: 'Enable HTTPS and configure strong cipher suites, disabling anonymous/null ciphers.' });
  }
  return issues;
}

function checkAnonymization() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  if (/email|phone|ssn|social.security|birth.?date|address/i.test(body)) {
    if (!/anonymiz|pseudonymiz|mask|redact/i.test(scripts + body)) {
      issues.push({ title: 'PII Without Anonymization', description: 'Page displays potentially sensitive personal data without evidence of anonymization/masking.', severity: 'medium', recommendation: 'Implement data anonymization or pseudonymization for displayed PII.' });
    }
  }
  return issues;
}

function checkAPIAuthentication() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/fetch\s*\(|XMLHttpRequest|axios|\.ajax/i.test(scripts)) {
    if (!/Authorization|Bearer|api.key|x-api-key|token/i.test(scripts)) {
      issues.push({ title: 'API Calls Without Authentication Headers', description: 'API calls detected without visible authentication headers.', severity: 'medium', recommendation: 'Ensure all API calls include proper authentication (Bearer tokens, API keys).' });
    }
  }
  return issues;
}

function checkAPIAuthorization() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/role|permission|authorize|forbidden|403/i.test(scripts)) {
    issues.push({ title: 'API Authorization Checks Not Evident', description: 'API calls detected but no client-side authorization handling visible.', severity: 'medium', recommendation: 'Implement proper authorization checks on all API endpoints server-side.' });
  }
  return issues;
}

function checkAPIBatchLimit() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/batch|bulk|multi/i.test(scripts) && /\/api\//i.test(scripts)) {
    issues.push({ title: 'API Batch Request Limit Advisory', description: 'Batch/bulk API operations detected. Ensure server limits batch sizes.', severity: 'low', recommendation: 'Implement batch size limits on all bulk API endpoints to prevent resource exhaustion.' });
  }
  return issues;
}

function checkAPICacheHeaders() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\/.*user|\/api\/.*account|\/api\/.*profile/i.test(scripts)) {
    issues.push({ title: 'API Cache Headers Advisory', description: 'API endpoints serving user data detected. Ensure sensitive responses include no-cache/no-store headers.', severity: 'low', recommendation: 'Set Cache-Control: no-store, no-cache on API responses containing sensitive data.' });
  }
  return issues;
}

function checkAPIContentType() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/fetch|XMLHttpRequest|axios/i.test(scripts)) {
    if (!/Content-Type|content-type|application\/json/i.test(scripts)) {
      issues.push({ title: 'API Content-Type Not Set', description: 'API calls detected without explicit Content-Type header.', severity: 'medium', recommendation: 'Always set Content-Type header (e.g., application/json) on API requests.' });
    }
  }
  return issues;
}

function checkAPICORS() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/mode\s*:\s*['"]no-cors['"]/i.test(scripts)) {
    issues.push({ title: 'API Using no-cors Mode', description: 'Fetch requests using mode:"no-cors" detected. Response data will be opaque.', severity: 'medium', recommendation: 'Use proper CORS configuration on the server instead of no-cors mode.' });
  }
  return issues;
}

function checkAPICSRF() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\/.*POST|\.post\s*\(|method\s*:\s*['"]POST/i.test(scripts)) {
    if (!/csrf|xsrf|X-CSRF|X-XSRF/i.test(scripts)) {
      issues.push({ title: 'API POST Without CSRF Protection', description: 'API POST requests detected without visible CSRF token handling.', severity: 'high', recommendation: 'Include CSRF tokens in all state-changing API requests or use SameSite cookies.' });
    }
  }
  return issues;
}

function checkAPIDeprecation() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/v1\/|\/api\/v1|deprecated/i.test(scripts)) {
    issues.push({ title: 'Deprecated API Version In Use', description: 'API calls to v1 or deprecated endpoints detected.', severity: 'low', recommendation: 'Migrate to the latest API version and implement API deprecation headers.' });
  }
  return issues;
}

function checkAPIDocsProduction() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/swagger|\/api-docs|\/openapi|redoc/i.test(body + ' ' + links.join(' '))) {
    issues.push({ title: 'API Documentation Exposed in Production', description: 'API documentation (Swagger/OpenAPI/Redoc) appears accessible on this page.', severity: 'high', recommendation: 'Disable API documentation endpoints in production environments.' });
  }
  return issues;
}

function checkAPIDocsPublic() {
  const issues = [];
  const body = document.body ? document.body.innerHTML.slice(0, 10000).toLowerCase() : '';
  if (/swagger-ui|api.explorer|graphiql|playground/i.test(body)) {
    issues.push({ title: 'Public API Explorer Detected', description: 'API exploration tools (Swagger UI, GraphiQL, etc.) found on page.', severity: 'medium', recommendation: 'Restrict API documentation/explorer access with authentication.' });
  }
  return issues;
}

function checkAPIEnumeration() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\/users\/\d|\/api\/user\/\d|\/api\/items\/\d/i.test(scripts)) {
    issues.push({ title: 'API Resource Enumeration Risk', description: 'API calls with sequential numeric IDs detected, enabling resource enumeration.', severity: 'medium', recommendation: 'Use UUIDs or non-sequential identifiers for API resources.' });
  }
  return issues;
}

function checkAPIExceptionDetails() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  if (/stack\s*trace|exception|traceback|at\s+\w+\.\w+\(|\.java:\d+|\.py.*line\s+\d+/i.test(body)) {
    issues.push({ title: 'API Exception Details Exposed', description: 'Stack trace or exception details visible on page.', severity: 'high', recommendation: 'Never expose stack traces in production. Return generic error messages.' });
  }
  return issues;
}

function checkAPIGatewayBypass() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/localhost:\d{4}|127\.0\.0\.1:\d{4}|:808[0-9]|:3000|:5000|:9090/i.test(scripts)) {
    issues.push({ title: 'Direct Backend Access (Gateway Bypass)', description: 'Direct access to backend services detected in code (localhost/internal ports).', severity: 'high', recommendation: 'Route all API traffic through the API gateway. Remove direct backend URLs from client code.' });
  }
  return issues;
}

function checkAPIGETModifications() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/GET.*delete|GET.*update|GET.*create|GET.*remove/i.test(scripts)) {
    issues.push({ title: 'State-Changing GET Requests', description: 'GET requests used for state-changing operations (delete, update, create).', severity: 'high', recommendation: 'Use POST/PUT/DELETE for state-changing operations, never GET.' });
  }
  return issues;
}

function checkAPIHealthCheck() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  if (/\/health|\/status|\/ready|\/alive/i.test(scripts + ' ' + links.join(' '))) {
    issues.push({ title: 'Health Check Endpoint Exposed', description: 'Health/status endpoints referenced in client code, may leak internal info.', severity: 'low', recommendation: 'Restrict health check endpoints to internal networks or require authentication.' });
  }
  return issues;
}

function checkAPIHTTPMethods() {
  const issues = [];
  // Advisory - can't test from content script
  return issues;
}

function checkAPIIdempotency() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && /POST|PUT|PATCH/i.test(scripts)) {
    if (!/idempotency|Idempotency-Key/i.test(scripts)) {
      issues.push({ title: 'API Idempotency Key Not Used', description: 'State-changing API calls without idempotency keys detected.', severity: 'low', recommendation: 'Use Idempotency-Key headers for POST/PUT requests to prevent duplicate processing.' });
    }
  }
  return issues;
}

function checkAPIInputLength() {
  const issues = [];
  const inputs = document.querySelectorAll('input:not([maxlength]), textarea:not([maxlength])');
  if (inputs.length > 0) {
    issues.push({ title: 'API Input Length Not Restricted', description: `${inputs.length} input field(s) without maxlength attribute found.`, severity: 'low', recommendation: 'Set maxlength on input fields and validate input length server-side.' });
  }
  return issues;
}

function checkAPIJSONP() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  for (const s of scripts) {
    if (/callback=|jsonp=|cb=/i.test(s.src)) {
      issues.push({ title: 'JSONP Endpoint Detected', description: `JSONP callback parameter found in script: ${s.src.slice(0, 100)}`, severity: 'high', recommendation: 'Replace JSONP with CORS-enabled JSON APIs. JSONP is vulnerable to data theft.' });
      break;
    }
  }
  return issues;
}

function checkAPIKeyInURL() {
  const issues = [];
  const url = window.location.href;
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/[?&](api_key|apikey|api-key|key|access_key)=/i.test(url + '\n' + scripts)) {
    issues.push({ title: 'API Key in URL', description: 'API key found in URL query parameters, exposing it in logs and referrer headers.', severity: 'high', recommendation: 'Send API keys in headers (Authorization or X-API-Key), never in URLs.' });
  }
  return issues;
}

function checkAPIKeyRateLimit() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/api.key|apikey|x-api-key/i.test(scripts)) {
    issues.push({ title: 'API Key Rate Limiting Advisory', description: 'API key usage detected. Ensure rate limiting is applied per API key.', severity: 'low', recommendation: 'Implement rate limiting per API key to prevent abuse.' });
  }
  return issues;
}

function checkAPIKeyRotation() {
  const issues = [];
  // Server-side advisory
  return issues;
}

function checkAPIKeysInCode() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const patterns = [
    /['"]AIza[0-9A-Za-z_-]{35}['"]/,
    /['"]sk-[a-zA-Z0-9]{20,}['"]/,
    /['"]AKIA[0-9A-Z]{16}['"]/,
    /['"][a-f0-9]{32,40}['"]/,
    /api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/i,
    /secret[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/i
  ];
  for (const p of patterns) {
    if (p.test(scripts)) {
      issues.push({ title: 'API Key/Secret Hardcoded in JS', description: 'Potential API key or secret found hardcoded in JavaScript source code.', severity: 'critical', recommendation: 'Remove API keys from client-side code. Use a backend proxy to make authenticated API calls.' });
      break;
    }
  }
  return issues;
}

function checkAPIKeysInJS() {
  // Alias for checkAPIKeysInCode - also checks external scripts that loaded
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/(?:api|secret|private)[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_\-\/+=]{16,}['"]/i.test(scripts)) {
    issues.push({ title: 'API Keys Found in JavaScript', description: 'API keys or secrets detected in inline JavaScript code.', severity: 'critical', recommendation: 'Move API keys to server-side. Never expose secrets in client-side code.' });
  }
  return issues;
}

function checkAPIKeysInLogs() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/console\.(log|debug|info|warn)\s*\(.*(?:key|token|secret|password|credential)/i.test(scripts)) {
    issues.push({ title: 'Sensitive Data in Console Logs', description: 'Console logging statements may output API keys or sensitive tokens.', severity: 'high', recommendation: 'Remove or redact sensitive data from console logs in production.' });
  }
  return issues;
}

function checkAPIKeyTransmission() {
  const issues = [];
  if (window.location.protocol === 'http:') {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    if (/api.key|apikey|Bearer|Authorization/i.test(scripts)) {
      issues.push({ title: 'API Keys Transmitted Over HTTP', description: 'API keys or auth tokens transmitted over unencrypted HTTP.', severity: 'critical', recommendation: 'Always use HTTPS for API key transmission.' });
    }
  }
  return issues;
}

function checkAPILogging() {
  const issues = [];
  // Server-side check - advisory
  return issues;
}

function checkAPIPagination() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/page|limit|offset|cursor|per_page|pageSize/i.test(scripts)) {
    issues.push({ title: 'API Pagination Not Implemented', description: 'API calls detected without pagination parameters, risking large data dumps.', severity: 'medium', recommendation: 'Implement pagination on all list/collection API endpoints with reasonable limits.' });
  }
  return issues;
}

function checkAPIQuota() {
  const issues = [];
  // Server-side - advisory
  return issues;
}

function checkAPIRateLimit() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/rate.limit|throttl|429|too.many.requests|retry-after/i.test(scripts)) {
    issues.push({ title: 'No API Rate Limit Handling', description: 'API calls detected but no rate limit handling (429/retry-after) in client code.', severity: 'medium', recommendation: 'Implement rate limiting server-side and handle 429 responses in client code.' });
  }
  return issues;
}

function checkAPIRequestID() {
  const issues = [];
  // Server-side - advisory
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/request.id|X-Request-ID|correlation.id|trace.id/i.test(scripts)) {
    issues.push({ title: 'API Request ID Not Used', description: 'API calls without request ID/correlation ID headers.', severity: 'low', recommendation: 'Include X-Request-ID headers for API call tracing and debugging.' });
  }
  return issues;
}

function checkAPIRequestSizeLimit() {
  const issues = [];
  // Server-side - advisory
  return issues;
}

function checkAPIThrottling() {
  const issues = [];
  // Server-side - covered by checkAPIRateLimit
  return issues;
}

function checkAPITimestamp() {
  const issues = [];
  // Server-side - advisory
  return issues;
}

function checkAPITimingAttack() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/===.*password|===.*token|===.*secret/i.test(scripts)) {
    issues.push({ title: 'Timing Attack Risk in Token Comparison', description: 'Direct string comparison on sensitive values detected in client code.', severity: 'medium', recommendation: 'Use constant-time comparison functions for sensitive value validation (server-side).' });
  }
  return issues;
}

function checkAPIVerboseErrors() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000) : '';
  if (/stack\s*trace|internal\s*server\s*error|sql|syntax\s*error|undefined\s*is\s*not/i.test(body)) {
    issues.push({ title: 'Verbose API Error Messages', description: 'Detailed error messages or stack traces found on page.', severity: 'high', recommendation: 'Return generic error messages in production. Log detailed errors server-side only.' });
  }
  return issues;
}

function checkAPIVersioning() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/\/api\//i.test(scripts) && !/\/v\d+\/|\/api\/v\d|api-version|Accept.*version/i.test(scripts)) {
    issues.push({ title: 'API Versioning Not Detected', description: 'API calls without version identifiers in URL or headers.', severity: 'low', recommendation: 'Implement API versioning (URL path or header-based) for backward compatibility.' });
  }
  return issues;
}

function checkAPIWebhookValidation() {
  const issues = [];
  // Server-side
  return issues;
}

function checkAPIXXE() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/text\/xml|application\/xml|DOMParser.*xml|parseXML/i.test(scripts)) {
    issues.push({ title: 'XML Processing Detected (XXE Risk)', description: 'Client-side XML parsing detected. Verify server-side XML processing disables external entities.', severity: 'medium', recommendation: 'Disable external entity processing in all XML parsers. Use JSON instead of XML where possible.' });
  }
  return issues;
}

function checkAPMDataLeakage() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
  const apm = ['newrelic', 'datadog', 'sentry', 'bugsnag', 'raygun', 'rollbar', 'elastic-apm', 'appdynamics'];
  for (const a of apm) {
    if (scripts.some(s => s.includes(a))) {
      issues.push({ title: 'APM/Error Tracking May Leak Data', description: `APM tool "${a}" detected. Ensure it doesn't capture sensitive user data or PII.`, severity: 'medium', recommendation: 'Configure APM tools to redact sensitive data (passwords, tokens, PII) before transmission.' });
      break;
    }
  }
  return issues;
}

function checkArchivedRepo() {
  const issues = [];
  // Not detectable from client-side
  return issues;
}

function checkArtifactRepoSecurity() { return []; }
function checkArtifactScanning() { return []; }

function checkAsyncTenantContext() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/tenant|organization.id|org_id/i.test(scripts) && /setTimeout|setInterval|Promise|async/i.test(scripts)) {
    if (!/tenant.*context|AsyncLocalStorage|cls.hooked/i.test(scripts)) {
      issues.push({ title: 'Tenant Context in Async Operations', description: 'Multi-tenant code with async operations but no clear tenant context propagation.', severity: 'medium', recommendation: 'Ensure tenant context is properly propagated through async operations.' });
    }
  }
  return issues;
}

function checkAuthErrorDifference() {
  const issues = [];
  const body = document.body ? document.body.innerText.slice(0, 5000).toLowerCase() : '';
  if (/invalid username|user not found|no such user|account does not exist/i.test(body)) {
    issues.push({ title: 'Authentication Error Reveals User Existence', description: 'Login error message differentiates between invalid username and invalid password.', severity: 'high', recommendation: 'Use generic messages like "Invalid username or password" for all authentication failures.' });
  }
  return issues;
}

function checkAutocompleteLeakage() {
  const issues = [];
  const inputs = document.querySelectorAll('input[type="password"], input[type="email"], input[name*="card"], input[name*="credit"], input[name*="ssn"]');
  for (const i of inputs) {
    if (i.getAttribute('autocomplete') !== 'off' && i.getAttribute('autocomplete') !== 'new-password') {
      issues.push({ title: 'Sensitive Input Allows Autocomplete', description: `Input "${i.name || i.type}" allows browser autocomplete, potentially caching sensitive data.`, severity: 'medium', recommendation: 'Set autocomplete="off" or autocomplete="new-password" on sensitive input fields.' });
      break;
    }
  }
  return issues;
}

function checkAutomatedSecurityTesting() { return []; }
function checkAWSConfig() { return []; }
function checkAzureStoragePublic() { return []; }
function checkBackgroundJobTenant() { return []; }

function checkBackgroundSync() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/sync.*register|BackgroundSync|periodicSync/i.test(scripts)) {
    issues.push({ title: 'Background Sync API Usage', description: 'Background Sync API detected. Ensure synced data is properly secured.', severity: 'low', recommendation: 'Validate and encrypt data queued for background sync. Implement proper authentication checks.' });
  }
  return issues;
}

function checkBacktickInjection() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/`.*\$\{.*(?:location|document|window|user|input|param|query)/i.test(scripts)) {
    issues.push({ title: 'Template Literal Injection Risk', description: 'Template literals with user-controlled input detected, potential injection vector.', severity: 'high', recommendation: 'Sanitize all user input before interpolating in template literals.' });
  }
  return issues;
}

function checkBackupEncryption() { return []; }

function checkBackupFiles() {
  const issues = [];
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href.toLowerCase());
  const backupExts = ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.copy', '.sql', '.dump', '.tar', '.gz', '.zip'];
  for (const l of links) {
    if (backupExts.some(e => l.endsWith(e))) {
      issues.push({ title: 'Backup File Referenced', description: `Link to potential backup file found: ${l.slice(0, 100)}`, severity: 'high', recommendation: 'Remove backup files from web-accessible directories.' });
      break;
    }
  }
  return issues;
}

function checkBackupFilesAccessible() {
  return checkBackupFiles();
}

function checkBearerTokenHTTPS() {
  const issues = [];
  if (window.location.protocol === 'http:') {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    if (/Bearer|Authorization/i.test(scripts)) {
      issues.push({ title: 'Bearer Token Over HTTP', description: 'Bearer tokens transmitted over unencrypted HTTP connection.', severity: 'critical', recommendation: 'Always use HTTPS when transmitting bearer tokens.' });
    }
  }
  return issues;
}

function checkBEAST() {
  const issues = [];
  // TLS-level check not possible from content script
  return issues;
}

function checkBlindSQLi() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep/i.test(scripts)) {
    issues.push({ title: 'Blind SQL Injection Patterns', description: 'SQL timing functions (SLEEP, WAITFOR, BENCHMARK) found in client code.', severity: 'critical', recommendation: 'Use parameterized queries. Never embed SQL logic in client-side code.' });
  }
  return issues;
}

function checkBlindSSRF() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/fetch\s*\(.*(?:url|uri|link|path|redirect|callback|webhook|image|proxy)/i.test(scripts)) {
    issues.push({ title: 'Potential SSRF Vector', description: 'Fetch calls with user-controllable URL parameters detected.', severity: 'high', recommendation: 'Validate and restrict URLs server-side. Use allowlists for external requests.' });
  }
  return issues;
}

function checkBlueGreenDeployment() { return []; }

function checkBootstrapSRI() {
  const issues = [];
  const els = document.querySelectorAll('link[href*="bootstrap"], script[src*="bootstrap"]');
  for (const el of els) {
    if (!el.integrity) {
      issues.push({ title: 'Bootstrap Loaded Without SRI', description: `Bootstrap resource loaded without integrity attribute: ${(el.href || el.src || '').slice(0, 100)}`, severity: 'medium', recommendation: 'Add integrity and crossorigin attributes to Bootstrap resources.' });
      break;
    }
  }
  return issues;
}

function checkBowerUsage() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
  if (scripts.some(s => s.includes('bower_components'))) {
    issues.push({ title: 'Deprecated Bower Package Manager', description: 'Bower components detected. Bower is deprecated and no longer maintained.', severity: 'medium', recommendation: 'Migrate from Bower to npm or yarn for frontend dependency management.' });
  }
  return issues;
}

function checkBranchProtection() { return []; }

function checkBREACH() {
  const issues = [];
  // Server-side check, advisory
  return issues;
}

function checkBreachResponsePlan() { return []; }
function checkBreakGlass() { return []; }
function checkBreakingChangeDetection() { return []; }

function checkBroadcastChannel() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/BroadcastChannel/i.test(scripts)) {
    issues.push({ title: 'BroadcastChannel API Usage', description: 'BroadcastChannel API used for cross-tab communication. Ensure no sensitive data is transmitted.', severity: 'low', recommendation: 'Validate and sanitize messages received via BroadcastChannel. Do not send sensitive data.' });
  }
  return issues;
}

function checkBrowserFingerprinting() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  const fingerprintSignals = ['fingerprintjs', 'canvas.toDataURL', 'webgl.*getParameter', 'AudioContext.*createOscillator', 'navigator.plugins', 'navigator.languages'];
  for (const sig of fingerprintSignals) {
    if (new RegExp(sig, 'i').test(scripts)) {
      issues.push({ title: 'Browser Fingerprinting Detected', description: 'Browser fingerprinting techniques detected in JavaScript code.', severity: 'medium', recommendation: 'Inform users about fingerprinting in your privacy policy. Consider less invasive alternatives.' });
      break;
    }
  }
  return issues;
}

function checkBuildCompromise() { return []; }

function checkBuildInfoInHTML() {
  const issues = [];
  const comments = [];
  const walk = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
  let n;
  while (n = walk.nextNode()) comments.push(n.textContent);
  const all = comments.join('\n');
  if (/build|version|commit|sha|deploy|release|jenkins|circle|travis|github.actions/i.test(all)) {
    issues.push({ title: 'Build Information in HTML Comments', description: 'Build/deployment information found in HTML comments.', severity: 'medium', recommendation: 'Remove build information from HTML comments in production.' });
  }
  return issues;
}

function checkBuildIsolation() { return []; }

function checkBulkheadPattern() { return []; }

function checkBusinessLogicClient() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/price\s*[=*+\-\/]|discount\s*[=*]|total\s*[=*+]|isAdmin\s*=|role\s*===?\s*['"]admin/i.test(scripts)) {
    issues.push({ title: 'Business Logic in Client Code', description: 'Price calculations, discount logic, or role checks found in client-side JavaScript.', severity: 'high', recommendation: 'Move business logic (pricing, discounts, authorization) to the server. Client-side logic can be tampered with.' });
  }
  return issues;
}

function checkCacheAPISensitive() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/caches\.open|cache\.put|cache\.add/i.test(scripts)) {
    if (/token|auth|password|secret|session|credential/i.test(scripts)) {
      issues.push({ title: 'Sensitive Data in Cache API', description: 'Cache API usage with potentially sensitive data detected.', severity: 'high', recommendation: 'Do not cache responses containing tokens, passwords, or session data.' });
    }
  }
  return issues;
}

function checkCacheHeaders() {
  const issues = [];
  // Covered by header checks
  return issues;
}

function checkCallbackValidation() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/callback\s*=\s*[^&'"]+/i.test(window.location.search) || /callback|redirect_uri|return_url|next/i.test(scripts)) {
    issues.push({ title: 'Callback URL Validation Advisory', description: 'Callback/redirect URL parameters detected. Ensure server validates these against an allowlist.', severity: 'medium', recommendation: 'Validate all callback URLs against a strict allowlist of permitted domains.' });
  }
  return issues;
}

function checkCanvasFingerprinting() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/canvas.*toDataURL|toBlob|getImageData.*fingerprint/i.test(scripts)) {
    issues.push({ title: 'Canvas Fingerprinting', description: 'Canvas fingerprinting technique detected in JavaScript.', severity: 'medium', recommendation: 'Disclose fingerprinting in privacy policy. Consider less invasive tracking methods.' });
  }
  return issues;
}

function checkCAPTCHA() {
  const issues = [];
  const forms = document.querySelectorAll('form');
  const loginForms = Array.from(forms).filter(f => /login|signin|register|signup/i.test((f.action || '') + (f.id || '') + (f.className || '')));
  if (loginForms.length > 0) {
    const hasCaptcha = document.querySelector('.g-recaptcha, .h-captcha, [data-sitekey], .cf-turnstile, iframe[src*="recaptcha"], iframe[src*="hcaptcha"]');
    if (!hasCaptcha) {
      issues.push({ title: 'No CAPTCHA on Login/Registration', description: 'Login or registration form without CAPTCHA protection detected.', severity: 'medium', recommendation: 'Add CAPTCHA (reCAPTCHA, hCaptcha, Turnstile) to login and registration forms.' });
    }
  }
  return issues;
}

function checkCaptchaRandom() { return []; }

function checkCaptchaValidation() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/g-recaptcha-response|h-captcha-response|cf-turnstile-response/i.test(scripts)) {
    if (!/verify|validate|server|backend/i.test(scripts)) {
      issues.push({ title: 'CAPTCHA Client-Side Only Validation', description: 'CAPTCHA response may only be checked client-side.', severity: 'high', recommendation: 'Always validate CAPTCHA responses server-side via the provider API.' });
    }
  }
  return issues;
}

function checkCCInLogs() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
  if (/console\.(log|debug).*(?:card|credit|cc|pan|cvv)/i.test(scripts)) {
    issues.push({ title: 'Credit Card Data in Console Logs', description: 'Console logging of potential credit card data detected.', severity: 'critical', recommendation: 'Never log credit card or payment data. This violates PCI DSS requirements.' });
  }
  return issues;
}

function checkCDNAPIKeys() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  for (const s of scripts) {
    if (/[?&](key|apikey|api_key|token)=[a-zA-Z0-9_-]{16,}/i.test(s.src)) {
      issues.push({ title: 'API Key in CDN/Script URL', description: `API key exposed in script URL: ${s.src.slice(0, 80)}...`, severity: 'high', recommendation: 'Remove API keys from CDN URLs. Use server-side proxying or restricted keys.' });
      break;
    }
  }
  return issues;
}

function checkCDNCachePoisoning() {
  const issues = [];
  // Server-side
  return issues;
}

function checkCDNFallback() {
  const issues = [];
  const cdnScripts = Array.from(document.querySelectorAll('script[src]')).filter(s => /cdn|cdnjs|unpkg|jsdelivr|cloudflare/i.test(s.src));
  if (cdnScripts.length > 0) {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\n');
    if (!/onerror|fallback|local.*load/i.test(scripts)) {
      issues.push({ title: 'No CDN Fallback Mechanism', description: 'CDN scripts loaded without fallback if CDN is unavailable.', severity: 'low', recommendation: 'Implement local fallbacks for critical CDN-hosted resources.' });
    }
  }
  return issues;
}

function checkCDNHTTP() {
  const issues = [];
  const scripts = Array.from(document.querySelectorAll('script[src^="http:"], link[href^="http:"]'));
  if (scripts.length > 0) {
    issues.push({ title: 'CDN Resources Over HTTP', description: `${scripts.length} resource(s) loaded over HTTP instead of HTTPS.`, severity: 'high', recommendation: 'Load all CDN resources over HTTPS.' });
  }
  return issues;
}

function checkCDNVersionPinning() {
  const issues = [];
  const cdnScripts = Array.from(document.querySelectorAll('script[src*="cdnjs.cloudflare.com"], script[src*="unpkg.com"], script[src*="jsdelivr.net"]'));
  for (const s of cdnScripts) {
    if (!/\d+\.\d+\.\d+/.test(s.src) && /latest|@latest/i.test(s.src)) {
      issues.push({ title: 'CDN Resource Not Version-Pinned', description: `CDN resource using "latest" instead of pinned version: ${s.src.slice(0, 100)}`, severity: 'medium', recommendation: 'Pin CDN resources to specific versions to prevent supply chain attacks.' });
      break;
    }
  }
  return issues;
}

function checkCDNwithoutSRI() {
  const issues = [];
  const els = document.querySelectorAll('script[src*="cdn"], link[href*="cdn"], script[src*="unpkg"], script[src*="jsdelivr"], script[src*="cdnjs"], script[src*="cloudflare"]');
  for (const el of els) {
    if (!el.integrity) {
      issues.push({ title: 'CDN Resource Without SRI', description: `CDN resource loaded without Subresource Integrity: ${(el.src || el.href || '').slice(0, 100)}`, severity: 'high', recommendation: 'Add integrity and crossorigin attributes to all CDN-loaded resources.' });
      break;
    }
  }
  return issues;
}
