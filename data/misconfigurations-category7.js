// ========================================
// SECURITY MISCONFIGURATIONS DATABASE
// Category 7: Client-Side Security
// Total: 100 Misconfigurations
// ========================================

const category7_ClientSideSecurity = [
  // JavaScript Security (1-25)
  {
    id: 601,
    category: "JavaScript Security",
    title: "eval() Used",
    description: "eval() executes arbitrary code from strings",
    severity: "high",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Never use eval(), use JSON.parse() or safer alternatives",
    checkFunction: "checkEvalUsage"
  },
  {
    id: 602,
    category: "JavaScript Security",
    title: "Function Constructor Used",
    description: "new Function() creates functions from strings",
    severity: "high",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid Function constructor, use proper functions",
    checkFunction: "checkFunctionConstructor"
  },
  {
    id: 603,
    category: "JavaScript Security",
    title: "setTimeout/setInterval with String",
    description: "Timer functions execute string code",
    severity: "high",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Pass function references, not strings, to timers",
    checkFunction: "checkTimerStrings"
  },
  {
    id: 604,
    category: "JavaScript Security",
    title: "innerHTML Used with User Data",
    description: "innerHTML can execute scripts from user input",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use textContent or sanitize HTML with DOMPurify",
    checkFunction: "checkInnerHTML"
  },
  {
    id: 605,
    category: "JavaScript Security",
    title: "document.write() Used",
    description: "document.write() can inject malicious content",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use DOM manipulation methods instead",
    checkFunction: "checkDocumentWrite"
  },
  {
    id: 606,
    category: "JavaScript Security",
    title: "Unsafe Inline Event Handlers",
    description: "onclick='...' inline handlers vulnerable to XSS",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use addEventListener() instead of inline handlers",
    checkFunction: "checkInlineEventHandlers"
  },
  {
    id: 607,
    category: "JavaScript Security",
    title: "location.href Assignment from User Input",
    description: "window.location with user data causes open redirect",
    severity: "medium",
    cwe: "CWE-601",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Validate URLs against allowlist before redirect",
    checkFunction: "checkLocationHrefAssignment"
  },
  {
    id: 608,
    category: "JavaScript Security",
    title: "Unsafe URL Scheme in href",
    description: "javascript: or data: URLs in links",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Only allow http: and https: schemes",
    checkFunction: "checkUnsafeURLScheme"
  },
  {
    id: 609,
    category: "JavaScript Security",
    title: "RegExp Denial of Service (ReDoS)",
    description: "Complex regex can cause CPU exhaustion",
    severity: "medium",
    cwe: "CWE-1333",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Avoid nested quantifiers, use regex analysis tools",
    checkFunction: "checkReDoS"
  },
  {
    id: 610,
    category: "JavaScript Security",
    title: "Prototype Pollution",
    description: "Object merge allows __proto__ injection",
    severity: "high",
    cwe: "CWE-1321",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate object keys, use Object.create(null)",
    checkFunction: "checkPrototypePollution"
  },
  {
    id: 611,
    category: "JavaScript Security",
    title: "Unsafe Object Creation",
    description: "Creating objects from untrusted JSON",
    severity: "medium",
    cwe: "CWE-502",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    recommendation: "Validate JSON structure, use schema validation",
    checkFunction: "checkUnsafeObjectCreation"
  },
  {
    id: 612,
    category: "JavaScript Security",
    title: "Client-Side Crypto Weak",
    description: "Using weak crypto libraries in browser",
    severity: "medium",
    cwe: "CWE-327",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Use Web Crypto API for cryptographic operations",
    checkFunction: "checkClientCrypto"
  },
  {
    id: 613,
    category: "JavaScript Security",
    title: "Source Maps in Production",
    description: "JavaScript source maps expose source code",
    severity: "medium",
    cwe: "CWE-540",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Disable source maps in production builds",
    checkFunction: "checkSourceMaps"
  },
  {
    id: 614,
    category: "JavaScript Security",
    title: "Console Statements in Production",
    description: "console.log() exposes debug information",
    severity: "low",
    cwe: "CWE-489",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Remove console statements from production code",
    checkFunction: "checkConsoleStatements"
  },
  {
    id: 615,
    category: "JavaScript Security",
    title: "debugger Statement Present",
    description: "debugger; statements in production code",
    severity: "low",
    cwe: "CWE-489",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Remove debugger statements before deployment",
    checkFunction: "checkDebuggerStatement"
  },
  {
    id: 616,
    category: "JavaScript Security",
    title: "window.name Manipulation",
    description: "window.name persists across domains",
    severity: "low",
    cwe: "CWE-346",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Don't store sensitive data in window.name",
    checkFunction: "checkWindowName"
  },
  {
    id: 617,
    category: "JavaScript Security",
    title: "Unsafe Strict Mode",
    description: "No 'use strict' directive",
    severity: "low",
    cwe: "CWE-1104",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Always use 'use strict' at function/module level",
    checkFunction: "checkStrictMode"
  },
  {
    id: 618,
    category: "JavaScript Security",
    title: "Dangerous Object Methods",
    description: "Using toString/valueOf on untrusted objects",
    severity: "low",
    cwe: "CWE-843",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate object types before calling methods",
    checkFunction: "checkDangerousObjectMethods"
  },
  {
    id: 619,
    category: "JavaScript Security",
    title: "API Keys in Client Code",
    description: "API keys hardcoded in JavaScript",
    severity: "critical",
    cwe: "CWE-798",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Use backend proxy for API calls, never expose keys",
    checkFunction: "checkAPIKeysInCode"
  },
  {
    id: 620,
    category: "JavaScript Security",
    title: "Secrets in JavaScript",
    description: "Passwords or tokens in client-side code",
    severity: "critical",
    cwe: "CWE-798",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Never include secrets in frontend code",
    checkFunction: "checkSecretsInJS"
  },
  {
    id: 621,
    category: "JavaScript Security",
    title: "Code Minification Missing",
    description: "JavaScript not minified in production",
    severity: "low",
    cwe: "CWE-1239",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Minify and obfuscate production JavaScript",
    checkFunction: "checkMinification"
  },
  {
    id: 622,
    category: "JavaScript Security",
    title: "Unsafe Dynamic Import",
    description: "import() with user-controlled paths",
    severity: "high",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate import paths against allowlist",
    checkFunction: "checkDynamicImport"
  },
  {
    id: 623,
    category: "JavaScript Security",
    title: "Client-Side Template Injection",
    description: "Template engines execute user input",
    severity: "high",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Use safe templating, escape user data",
    checkFunction: "checkClientTemplateInjection"
  },
  {
    id: 624,
    category: "JavaScript Security",
    title: "AJAX Cross-Domain Data Leakage",
    description: "fetch() exposes credentials across origins",
    severity: "medium",
    cwe: "CWE-346",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Use credentials: 'same-origin' for fetch()",
    checkFunction: "checkAJAXCredentials"
  },
  {
    id: 625,
    category: "JavaScript Security",
    title: "Client-Side Logic for Access Control",
    description: "Authorization decisions made in browser",
    severity: "critical",
    cwe: "CWE-602",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Always enforce access control on server",
    checkFunction: "checkClientSideAuth"
  },

  // DOM Manipulation (26-40)
  {
    id: 626,
    category: "DOM Manipulation",
    title: "DOM-Based XSS",
    description: "User input directly inserted into DOM",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Sanitize all user input before DOM insertion",
    checkFunction: "checkDOMXSS"
  },
  {
    id: 627,
    category: "DOM Manipulation",
    title: "Unsafe jQuery Methods",
    description: "Using .html() or .append() with user data",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use .text() instead, or sanitize with DOMPurify",
    checkFunction: "checkUnsafeJQuery"
  },
  {
    id: 628,
    category: "DOM Manipulation",
    title: "setAttribute with User Data",
    description: "Setting attributes with unsanitized input",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate attribute values, avoid javascript: URIs",
    checkFunction: "checkSetAttribute"
  },
  {
    id: 629,
    category: "DOM Manipulation",
    title: "insertAdjacentHTML Used Unsafely",
    description: "insertAdjacentHTML can execute scripts",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use createTextNode() or sanitize HTML",
    checkFunction: "checkInsertAdjacentHTML"
  },
  {
    id: 630,
    category: "DOM Manipulation",
    title: "Dangling Markup Injection",
    description: "Unclosed tags used to capture data",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Properly encode HTML, use CSP to prevent data exfiltration",
    checkFunction: "checkDanglingMarkup"
  },
  {
    id: 631,
    category: "DOM Manipulation",
    title: "MutationObserver Abuse",
    description: "Observers can detect security mechanisms",
    severity: "low",
    cwe: "CWE-1104",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Limit what DOM mutations expose",
    checkFunction: "checkMutationObserver"
  },
  {
    id: 632,
    category: "DOM Manipulation",
    title: "Shadow DOM Security Misconfiguration",
    description: "Shadow DOM not properly isolated",
    severity: "low",
    cwe: "CWE-668",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Use closed shadow roots for sensitive components",
    checkFunction: "checkShadowDOM"
  },
  {
    id: 633,
    category: "DOM Manipulation",
    title: "Custom Elements Security",
    description: "Web components accept untrusted input",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate all custom element attributes and properties",
    checkFunction: "checkCustomElements"
  },
  {
    id: 634,
    category: "DOM Manipulation",
    title: "Range API Misuse",
    description: "Range.createContextualFragment with user input",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Sanitize HTML before using Range API",
    checkFunction: "checkRangeAPI"
  },
  {
    id: 635,
    category: "DOM Manipulation",
    title: "DOM Clobbering",
    description: "Named elements override JavaScript properties",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use hasOwnProperty(), avoid global variable conflicts",
    checkFunction: "checkDOMClobbering"
  },
  {
    id: 636,
    category: "DOM Manipulation",
    title: "Unsafe SVG Insertion",
    description: "SVG elements can contain JavaScript",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Sanitize SVG content, remove script elements and event handlers",
    checkFunction: "checkUnsafeSVG"
  },
  {
    id: 637,
    category: "DOM Manipulation",
    title: "HTML5 Canvas Fingerprinting",
    description: "Canvas used for tracking without consent",
    severity: "low",
    cwe: "CWE-359",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Notify users about canvas fingerprinting, allow opt-out",
    checkFunction: "checkCanvasFingerprinting"
  },
  {
    id: 638,
    category: "DOM Manipulation",
    title: "WebGL Information Leakage",
    description: "WebGL exposes GPU information",
    severity: "low",
    cwe: "CWE-200",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Limit WebGL usage, be aware of fingerprinting",
    checkFunction: "checkWebGLLeakage"
  },
  {
    id: 639,
    category: "DOM Manipulation",
    title: "Selection API Data Leakage",
    description: "window.getSelection() exposes sensitive text",
    severity: "low",
    cwe: "CWE-200",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Disable text selection on sensitive content",
    checkFunction: "checkSelectionAPI"
  },
  {
    id: 640,
    category: "DOM Manipulation",
    title: "Clipboard API Abuse",
    description: "Clipboard.writeText() used without permission",
    severity: "low",
    cwe: "CWE-471",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Request clipboard permission, notify users",
    checkFunction: "checkClipboardAPI"
  },

  // Browser Storage (41-60)
  {
    id: 641,
    category: "Browser Storage",
    title: "Sensitive Data in localStorage",
    description: "Passwords or tokens in localStorage",
    severity: "high",
    cwe: "CWE-312",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Never store sensitive data in localStorage, use secure cookies",
    checkFunction: "checkLocalStorageSensitive"
  },
  {
    id: 642,
    category: "Browser Storage",
    title: "localStorage Without Encryption",
    description: "Unencrypted data in localStorage",
    severity: "medium",
    cwe: "CWE-311",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Encrypt data before storing, use Web Crypto API",
    checkFunction: "checkLocalStorageEncryption"
  },
  {
    id: 643,
    category: "Browser Storage",
    title: "sessionStorage Misuse",
    description: "Session data survives tab close",
    severity: "low",
    cwe: "CWE-613",
    owasp: "A07:2021 - Identification and Authentication Failures",
    recommendation: "Clear sessionStorage on logout, use httpOnly cookies for sessions",
    checkFunction: "checkSessionStorage"
  },
  {
    id: 644,
    category: "Browser Storage",
    title: "IndexedDB Without Access Control",
    description: "Any script can access IndexedDB",
    severity: "medium",
    cwe: "CWE-668",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Encrypt sensitive IndexedDB data",
    checkFunction: "checkIndexedDBSecurity"
  },
  {
    id: 645,
    category: "Browser Storage",
    title: "Web SQL Database Used",
    description: "Deprecated Web SQL still in use",
    severity: "medium",
    cwe: "CWE-1104",
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    recommendation: "Migrate to IndexedDB",
    checkFunction: "checkWebSQL"
  },
  {
    id: 646,
    category: "Browser Storage",
    title: "Cookie Overflow",
    description: "Storing too much data in cookies",
    severity: "low",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Use localStorage for large data, keep cookies minimal",
    checkFunction: "checkCookieOverflow"
  },
  {
    id: 647,
    category: "Browser Storage",
    title: "No Storage Quota Handling",
    description: "Application doesn't handle storage full errors",
    severity: "low",
    cwe: "CWE-755",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Check storage quota, handle quota exceeded errors",
    checkFunction: "checkStorageQuota"
  },
  {
    id: 648,
    category: "Browser Storage",
    title: "Cache API Stores Sensitive Data",
    description: "Service worker cache contains credentials",
    severity: "high",
    cwe: "CWE-524",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Don't cache sensitive endpoints, use cache-control: no-store",
    checkFunction: "checkCacheAPISensitive"
  },
  {
    id: 649,
    category: "Browser Storage",
    title: "Storage Event Listener Missing",
    description: "Not detecting storage changes from other tabs",
    severity: "low",
    cwe: "CWE-1021",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Listen to storage events for cross-tab communication",
    checkFunction: "checkStorageEvents"
  },
  {
    id: 650,
    category: "Browser Storage",
    title: "Storage Data Not Cleared on Logout",
    description: "localStorage/sessionStorage persists after logout",
    severity: "medium",
    cwe: "CWE-459",
    owasp: "A07:2021 - Identification and Authentication Failures",
    recommendation: "Clear all storage on logout",
    checkFunction: "checkStorageClearOnLogout"
  },
  {
    id: 651,
    category: "Browser Storage",
    title: "Cookie SameSite Not Set",
    description: "Cookies lack SameSite attribute",
    severity: "high",
    cwe: "CWE-1275",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Set SameSite=Strict or Lax for all cookies",
    checkFunction: "checkCookieSameSite"
  },
  {
    id: 652,
    category: "Browser Storage",
    title: "Cookie Prefix Not Used",
    description: "Missing __Host- or __Secure- prefix",
    severity: "medium",
    cwe: "CWE-614",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Use __Host- prefix for critical cookies",
    checkFunction: "checkCookiePrefix"
  },
  {
    id: 653,
    category: "Browser Storage",
    title: "Cookie Domain Too Broad",
    description: "Cookie accessible to many subdomains",
    severity: "medium",
    cwe: "CWE-668",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Set specific domain, avoid .example.com",
    checkFunction: "checkCookieDomain"
  },
  {
    id: 654,
    category: "Browser Storage",
    title: "Cookie Path Too Broad",
    description: "Cookie Path=/ when more specific path possible",
    severity: "low",
    cwe: "CWE-668",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Use specific path for cookies",
    checkFunction: "checkCookiePath"
  },
  {
    id: 655,
    category: "Browser Storage",
    title: "Third-Party Cookies Not Blocked",
    description: "Allowing third-party cookies",
    severity: "low",
    cwe: "CWE-359",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Block third-party cookies, use first-party only",
    checkFunction: "checkThirdPartyCookies"
  },
  {
    id: 656,
    category: "Browser Storage",
    title: "Supercookie Usage",
    description: "Using ETags or other persistent identifiers",
    severity: "medium",
    cwe: "CWE-359",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Avoid supercookies, respect user privacy",
    checkFunction: "checkSupercookies"
  },
  {
    id: 657,
    category: "Browser Storage",
    title: "Browser Fingerprinting Excessive",
    description: "Collecting too many device characteristics",
    severity: "low",
    cwe: "CWE-359",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Minimize fingerprinting, use consent mechanism",
    checkFunction: "checkBrowserFingerprinting"
  },
  {
    id: 658,
    category: "Browser Storage",
    title: "Storage Expiration Not Set",
    description: "Cached data never expires",
    severity: "low",
    cwe: "CWE-613",
    owasp: "A07:2021 - Identification and Authentication Failures",
    recommendation: "Implement expiration timestamps for stored data",
    checkFunction: "checkStorageExpiration"
  },
  {
    id: 659,
    category: "Browser Storage",
    title: "SharedWorker Data Leakage",
    description: "SharedWorker accessible across origins",
    severity: "medium",
    cwe: "CWE-346",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Validate origin in SharedWorker, limit data sharing",
    checkFunction: "checkSharedWorker"
  },
  {
    id: 660,
    category: "Browser Storage",
    title: "BroadcastChannel Without Origin Check",
    description: "BroadcastChannel allows cross-tab message spoofing",
    severity: "low",
    cwe: "CWE-346",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Validate message origin in BroadcastChannel listeners",
    checkFunction: "checkBroadcastChannel"
  },

  // WebSockets & Real-Time (61-75)
  {
    id: 661,
    category: "WebSockets",
    title: "WebSocket Over WS Not WSS",
    description: "Unencrypted WebSocket connection",
    severity: "high",
    cwe: "CWE-319",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Use wss:// instead of ws://",
    checkFunction: "checkWebSocketEncryption"
  },
  {
    id: 662,
    category: "WebSockets",
    title: "WebSocket Origin Not Validated",
    description: "Server accepts WebSocket from any origin",
    severity: "high",
    cwe: "CWE-346",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Validate Origin header on WebSocket handshake",
    checkFunction: "checkWebSocketOrigin"
  },
  {
    id: 663,
    category: "WebSockets",
    title: "WebSocket No Authentication",
    description: "WebSocket connection without auth token",
    severity: "critical",
    cwe: "CWE-306",
    owasp: "A07:2021 - Identification and Authentication Failures",
    recommendation: "Authenticate WebSocket connections with JWT or session",
    checkFunction: "checkWebSocketAuth"
  },
  {
    id: 664,
    category: "WebSockets",
    title: "WebSocket Message Not Validated",
    description: "WebSocket messages accepted without validation",
    severity: "high",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate and sanitize all WebSocket messages",
    checkFunction: "checkWebSocketValidation"
  },
  {
    id: 665,
    category: "WebSockets",
    title: "WebSocket Rate Limiting Missing",
    description: "No limit on WebSocket message rate",
    severity: "medium",
    cwe: "CWE-770",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Implement rate limiting for WebSocket messages",
    checkFunction: "checkWebSocketRateLimit"
  },
  {
    id: 666,
    category: "WebSockets",
    title: "WebSocket Message Size Unlimited",
    description: "Accepting huge WebSocket frames",
    severity: "medium",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Limit WebSocket message size (e.g., 1MB)",
    checkFunction: "checkWebSocketMessageSize"
  },
  {
    id: 667,
    category: "WebSockets",
    title: "WebSocket Timeout Missing",
    description: "Idle WebSocket connections never close",
    severity: "low",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Close idle connections after timeout (e.g., 5 minutes)",
    checkFunction: "checkWebSocketTimeout"
  },
  {
    id: 668,
    category: "WebSockets",
    title: "WebSocket Reconnection Flood",
    description: "Client reconnects too aggressively",
    severity: "low",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Implement exponential backoff for reconnection",
    checkFunction: "checkWebSocketReconnect"
  },
  {
    id: 669,
    category: "WebSockets",
    title: "Server-Sent Events No Auth",
    description: "SSE endpoint accessible without authentication",
    severity: "high",
    cwe: "CWE-306",
    owasp: "A07:2021 - Identification and Authentication Failures",
    recommendation: "Authenticate SSE connections",
    checkFunction: "checkSSEAuth"
  },
  {
    id: 670,
    category: "WebSockets",
    title: "EventSource Over HTTP",
    description: "Server-Sent Events not encrypted",
    severity: "high",
    cwe: "CWE-319",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Use HTTPS for SSE connections",
    checkFunction: "checkEventSourceEncryption"
  },
  {
    id: 671,
    category: "WebSockets",
    title: "WebRTC Data Channel Unsecured",
    description: "WebRTC data channels without encryption",
    severity: "medium",
    cwe: "CWE-319",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Use DTLS for WebRTC data channels",
    checkFunction: "checkWebRTCSecurity"
  },
  {
    id: 672,
    category: "WebSockets",
    title: "WebRTC IP Leakage",
    description: "WebRTC exposes real IP behind VPN",
    severity: "low",
    cwe: "CWE-200",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Use ICE candidates policy to limit IP exposure",
    checkFunction: "checkWebRTCIPLeakage"
  },
  {
    id: 673,
    category: "WebSockets",
    title: "Long Polling Without Limits",
    description: "Long polling requests unlimited",
    severity: "medium",
    cwe: "CWE-770",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Limit concurrent long polling connections per user",
    checkFunction: "checkLongPolling"
  },
  {
    id: 674,
    category: "WebSockets",
    title: "WebSocket Fragmentation Attack",
    description: "Vulnerable to message fragmentation DoS",
    severity: "low",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Limit fragmented message count and total size",
    checkFunction: "checkWebSocketFragmentation"
  },
  {
    id: 675,
    category: "WebSockets",
    title: "Push Notification Security",
    description: "Push API used without user consent",
    severity: "medium",
    cwe: "CWE-1021",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Request push permission, allow easy unsubscribe",
    checkFunction: "checkPushNotifications"
  },

  // Service Workers & PWA (76-90)
  {
    id: 676,
    category: "Service Workers",
    title: "Service Worker Over HTTP",
    description: "Service worker served without HTTPS",
    severity: "critical",
    cwe: "CWE-319",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Service workers require HTTPS",
    checkFunction: "checkServiceWorkerHTTPS"
  },
  {
    id: 677,
    category: "Service Workers",
    title: "Service Worker Scope Too Broad",
    description: "Service worker controls entire domain",
    severity: "medium",
    cwe: "CWE-668",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Limit service worker scope to necessary paths",
    checkFunction: "checkServiceWorkerScope"
  },
  {
    id: 678,
    category: "Service Workers",
    title: "Service Worker Cache Poisoning",
    description: "Caching user-specific or sensitive data",
    severity: "high",
    cwe: "CWE-524",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Don't cache authenticated or user-specific responses",
    checkFunction: "checkServiceWorkerCachePoisoning"
  },
  {
    id: 679,
    category: "Service Workers",
    title: "Service Worker importScripts Unsafe",
    description: "Importing external scripts in service worker",
    severity: "high",
    cwe: "CWE-829",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    recommendation: "Avoid importScripts() or use SRI",
    checkFunction: "checkServiceWorkerImports"
  },
  {
    id: 680,
    category: "Service Workers",
    title: "Service Worker Update Check Missing",
    description: "Service worker never updates",
    severity: "medium",
    cwe: "CWE-1104",
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    recommendation: "Implement service worker update mechanism",
    checkFunction: "checkServiceWorkerUpdate"
  },
  {
    id: 681,
    category: "Service Workers",
    title: "Background Sync Abuse",
    description: "Background Sync API used excessively",
    severity: "low",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Limit background sync frequency and size",
    checkFunction: "checkBackgroundSync"
  },
  {
    id: 682,
    category: "Service Workers",
    title: "Service Worker Lifecycle Mishandled",
    description: "Old service worker prevents updates",
    severity: "low",
    cwe: "CWE-1021",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Implement proper skipWaiting() logic",
    checkFunction: "checkServiceWorkerLifecycle"
  },
  {
    id: 683,
    category: "Service Workers",
    title: "Web App Manifest Security",
    description: "Manifest allows untrusted scopes",
    severity: "medium",
    cwe: "CWE-610",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Validate manifest scope, use specific origins",
    checkFunction: "checkWebAppManifest"
  },
  {
    id: 684,
    category: "Service Workers",
    title: "PWA Install Prompt Abuse",
    description: "Aggressive install prompts annoy users",
    severity: "low",
    cwe: "CWE-1021",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Show install prompt at appropriate time",
    checkFunction: "checkPWAInstallPrompt"
  },
  {
    id: 685,
    category: "Service Workers",
    title: "Offline Functionality Misconfiguration",
    description: "Offline page exposes sensitive cached data",
    severity: "medium",
    cwe: "CWE-524",
    owasp: "A02:2021 - Cryptographic Failures",
    recommendation: "Show generic offline page, clear sensitive cache",
    checkFunction: "checkOfflineFunctionality"
  },
  {
    id: 686,
    category: "Service Workers",
    title: "Service Worker No CSP",
    description: "Service worker lacks Content Security Policy",
    severity: "medium",
    cwe: "CWE-1021",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Apply CSP to service worker responses",
    checkFunction: "checkServiceWorkerCSP"
  },
  {
    id: 687,
    category: "Service Workers",
    title: "Workbox Security Misconfiguration",
    description: "Workbox precache includes sensitive files",
    severity: "medium",
    cwe: "CWE-524",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Exclude sensitive endpoints from precache manifest",
    checkFunction: "checkWorkboxConfig"
  },
  {
    id: 688,
    category: "Service Workers",
    title: "Service Worker Cross-Origin Fetch",
    description: "Fetching cross-origin resources without CORS",
    severity: "medium",
    cwe: "CWE-942",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Use no-cors mode appropriately, validate responses",
    checkFunction: "checkServiceWorkerCORS"
  },
  {
    id: 689,
    category: "Service Workers",
    title: "Service Worker Message Validation",
    description: "postMessage to service worker not validated",
    severity: "medium",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate all messages sent to service workers",
    checkFunction: "checkServiceWorkerMessages"
  },
  {
    id: 690,
    category: "Service Workers",
    title: "Payment Request API Security",
    description: "Payment Handler without proper validation",
    severity: "high",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate payment data, use HTTPS, verify merchant",
    checkFunction: "checkPaymentRequestAPI"
  },

  // Client-Side Validation (91-100)
  {
    id: 691,
    category: "Client-Side Validation",
    title: "Client-Side Validation Only",
    description: "No server-side validation",
    severity: "critical",
    cwe: "CWE-602",
    owasp: "A03:2021 - Injection",
    recommendation: "Always validate on server, client-side is supplementary",
    checkFunction: "checkClientValidationOnly"
  },
  {
    id: 692,
    category: "Client-Side Validation",
    title: "HTML5 Validation Bypass",
    description: "Relying on HTML5 required/pattern attributes",
    severity: "high",
    cwe: "CWE-602",
    owasp: "A03:2021 - Injection",
    recommendation: "HTML5 validation easily bypassed, validate server-side",
    checkFunction: "checkHTML5ValidationBypass"
  },
  {
    id: 693,
    category: "Client-Side Validation",
    title: "Disabled Submit Button Security",
    description: "Submit button disabled until validation",
    severity: "medium",
    cwe: "CWE-602",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Disabled buttons easily bypassed, validate server-side",
    checkFunction: "checkDisabledSubmit"
  },
  {
    id: 694,
    category: "Client-Side Validation",
    title: "Hidden Form Field Security",
    description: "Hidden fields used for security decisions",
    severity: "high",
    cwe: "CWE-472",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Never trust hidden fields, validate server-side",
    checkFunction: "checkHiddenFields"
  },
  {
    id: 695,
    category: "Client-Side Validation",
    title: "File Upload Client Validation Only",
    description: "File type checked only in browser",
    severity: "high",
    cwe: "CWE-434",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate file type, size, and content on server",
    checkFunction: "checkFileUploadValidation"
  },
  {
    id: 696,
    category: "Client-Side Validation",
    title: "Price Validation Client-Side",
    description: "Product prices validated only in JavaScript",
    severity: "critical",
    cwe: "CWE-602",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Always validate prices server-side",
    checkFunction: "checkPriceValidation"
  },
  {
    id: 697,
    category: "Client-Side Validation",
    title: "Quantity Validation Missing",
    description: "Cart quantity modifiable to negative values",
    severity: "high",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate quantity ranges server-side",
    checkFunction: "checkQuantityValidation"
  },
  {
    id: 698,
    category: "Client-Side Validation",
    title: "Discount Code Client-Side",
    description: "Discount logic implemented in JavaScript",
    severity: "critical",
    cwe: "CWE-602",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Validate discount codes server-side",
    checkFunction: "checkDiscountValidation"
  },
  {
    id: 699,
    category: "Client-Side Validation",
    title: "Captcha Validation Client-Side",
    description: "Captcha checked only in browser",
    severity: "critical",
    cwe: "CWE-602",
    owasp: "A07:2021 - Identification and Authentication Failures",
    recommendation: "Always verify captcha server-side",
    checkFunction: "checkCaptchaValidation"
  },
  {
    id: 700,
    category: "Client-Side Validation",
    title: "Business Logic in Client Code",
    description: "Critical business rules implemented client-side",
    severity: "critical",
    cwe: "CWE-602",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Implement all business logic on server",
    checkFunction: "checkBusinessLogicClient"
  }
];

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { category7_ClientSideSecurity };
}
