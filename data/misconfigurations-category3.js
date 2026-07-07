// ========================================
// SECURITY MISCONFIGURATIONS DATABASE
// Category 3: Input Validation & Injection
// Total: 100 Misconfigurations
// ========================================

const category3_InputValidationInjection = [
  // Cross-Site Scripting (XSS) (1-25)
  {
    id: 201,
    category: "Cross-Site Scripting",
    title: "Reflected XSS in URL Parameters",
    description: "URL parameters reflected in page without encoding",
    severity: "critical",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "HTML-encode all user input before rendering. Use context-appropriate encoding",
    checkFunction: "checkReflectedXSS"
  },
  {
    id: 202,
    category: "Cross-Site Scripting",
    title: "Stored XSS in User Content",
    description: "User-submitted content stored and displayed without sanitization",
    severity: "critical",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Sanitize all user input before storage, encode on output",
    checkFunction: "checkStoredXSS"
  },
  {
    id: 203,
    category: "Cross-Site Scripting",
    title: "DOM-Based XSS",
    description: "Client-side JavaScript processes untrusted data unsafely",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid dangerous sinks (innerHTML, eval). Use textContent or DOMPurify",
    checkFunction: "checkDOMXSS"
  },
  {
    id: 204,
    category: "Cross-Site Scripting",
    title: "XSS in JavaScript String Context",
    description: "User input injected into JavaScript string without escaping",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "JavaScript-escape data in JS context or avoid inline JS entirely",
    checkFunction: "checkXSSJavaScriptContext"
  },
  {
    id: 205,
    category: "Cross-Site Scripting",
    title: "XSS in HTML Attribute Context",
    description: "Unescaped user input in HTML attributes",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "HTML-attribute-encode data in attributes, avoid event handlers",
    checkFunction: "checkXSSAttributeContext"
  },
  {
    id: 206,
    category: "Cross-Site Scripting",
    title: "XSS in CSS Context",
    description: "User input in style attributes or tags",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid user input in CSS, use CSS-specific escaping if necessary",
    checkFunction: "checkXSSCSSContext"
  },
  {
    id: 207,
    category: "Cross-Site Scripting",
    title: "XSS via File Upload",
    description: "Uploaded files served with incorrect Content-Type allowing script execution",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Set proper Content-Type, X-Content-Type-Options: nosniff, serve from different domain",
    checkFunction: "checkXSSFileUpload"
  },
  {
    id: 208,
    category: "Cross-Site Scripting",
    title: "XSS in SVG Files",
    description: "SVG files contain embedded JavaScript",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Sanitize SVG uploads, serve with Content-Disposition: attachment",
    checkFunction: "checkXSSSVG"
  },
  {
    id: 209,
    category: "Cross-Site Scripting",
    title: "XSS via JavaScript URL",
    description: "javascript: URLs allowed in href or src attributes",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate URL schemes, block javascript: and data: URLs where not needed",
    checkFunction: "checkXSSJavaScriptURL"
  },
  {
    id: 210,
    category: "Cross-Site Scripting",
    title: "XSS via Data URLs",
    description: "Data URLs allowed to execute scripts",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Restrict data: URLs via CSP, validate content type",
    checkFunction: "checkXSSDataURL"
  },
  {
    id: 211,
    category: "Cross-Site Scripting",
    title: "innerHTML Usage",
    description: "Using innerHTML with user-controlled data",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use textContent or DOMPurify library for sanitization",
    checkFunction: "checkInnerHTML"
  },
  {
    id: 212,
    category: "Cross-Site Scripting",
    title: "document.write Usage",
    description: "Using document.write with untrusted data",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid document.write, use DOM manipulation methods instead",
    checkFunction: "checkDocumentWrite"
  },
  {
    id: 213,
    category: "Cross-Site Scripting",
    title: "eval() with User Input",
    description: "eval() function used with user-controlled data",
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Never use eval(). Use JSON.parse() for JSON data",
    checkFunction: "checkEvalUsage"
  },
  {
    id: 214,
    category: "Cross-Site Scripting",
    title: "Function Constructor with User Input",
    description: "new Function() used with untrusted data",
    severity: "high",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid Function constructor with user input",
    checkFunction: "checkFunctionConstructor"
  },
  {
    id: 215,
    category: "Cross-Site Scripting",
    title: "setTimeout/setInterval with String",
    description: "setTimeout/setInterval using string argument with user data",
    severity: "high",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Use function references instead of strings in setTimeout/setInterval",
    checkFunction: "checkSetTimeoutString"
  },
  {
    id: 216,
    category: "Cross-Site Scripting",
    title: "jQuery HTML Methods Unsafe",
    description: "Using jQuery html(), append(), etc. with user input",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use text() method or sanitize input before html()",
    checkFunction: "checkJQueryHTML"
  },
  {
    id: 217,
    category: "Cross-Site Scripting",
    title: "Angular Bypass Security Trust",
    description: "Bypassing Angular's built-in sanitization",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid bypassSecurityTrust methods unless absolutely necessary",
    checkFunction: "checkAngularBypass"
  },
  {
    id: 218,
    category: "Cross-Site Scripting",
    title: "React dangerouslySetInnerHTML",
    description: "Using dangerouslySetInnerHTML with user content",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid dangerouslySetInnerHTML or use DOMPurify",
    checkFunction: "checkReactDangerouslySetInnerHTML"
  },
  {
    id: 219,
    category: "Cross-Site Scripting",
    title: "Vue v-html Directive",
    description: "Using v-html with untrusted content",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use v-text or sanitize content before v-html",
    checkFunction: "checkVueHTML"
  },
  {
    id: 220,
    category: "Cross-Site Scripting",
    title: "Template Injection",
    description: "Server-side template injection vulnerability",
    severity: "critical",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Use safe template rendering, escape template variables",
    checkFunction: "checkTemplateInjection"
  },
  {
    id: 221,
    category: "Cross-Site Scripting",
    title: "Markdown XSS",
    description: "Markdown rendering allows HTML/JavaScript",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use markdown sanitizer, disable raw HTML in markdown",
    checkFunction: "checkMarkdownXSS"
  },
  {
    id: 222,
    category: "Cross-Site Scripting",
    title: "Rich Text Editor XSS",
    description: "WYSIWYG editor allows dangerous HTML",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Configure editor to strip dangerous tags, sanitize output",
    checkFunction: "checkRichTextXSS"
  },
  {
    id: 223,
    category: "Cross-Site Scripting",
    title: "Mutation XSS (mXSS)",
    description: "HTML mutation during parsing creates XSS",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Use robust sanitization library (DOMPurify) that handles mXSS",
    checkFunction: "checkMutationXSS"
  },
  {
    id: 224,
    category: "Cross-Site Scripting",
    title: "XSS via Meta Tags",
    description: "User-controlled meta tag content",
    severity: "medium",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate and encode meta tag content",
    checkFunction: "checkMetaTagXSS"
  },
  {
    id: 225,
    category: "Cross-Site Scripting",
    title: "XSS in Error Messages",
    description: "Error messages reflect user input without encoding",
    severity: "high",
    cwe: "CWE-79",
    owasp: "A03:2021 - Injection",
    recommendation: "Encode user data in error messages, use generic errors",
    checkFunction: "checkErrorMessageXSS"
  },

  // SQL Injection (26-40)
  {
    id: 226,
    category: "SQL Injection",
    title: "SQL Injection in Login Form",
    description: "Authentication queries vulnerable to SQL injection",
    severity: "critical",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Use parameterized queries or prepared statements",
    checkFunction: "checkSQLiLogin"
  },
  {
    id: 227,
    category: "SQL Injection",
    title: "SQL Injection in Search Function",
    description: "Search parameters concatenated into SQL queries",
    severity: "critical",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Use ORM or parameterized queries for search",
    checkFunction: "checkSQLiSearch"
  },
  {
    id: 228,
    category: "SQL Injection",
    title: "Second-Order SQL Injection",
    description: "Stored data used in queries without sanitization",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate and parameterize even stored data in queries",
    checkFunction: "checkSecondOrderSQLi"
  },
  {
    id: 229,
    category: "SQL Injection",
    title: "Blind SQL Injection",
    description: "Application vulnerable to time-based or boolean blind SQLi",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Use parameterized queries, limit database error exposure",
    checkFunction: "checkBlindSQLi"
  },
  {
    id: 230,
    category: "SQL Injection",
    title: "SQL Injection in ORDER BY Clause",
    description: "Dynamic ORDER BY with user input",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Whitelist allowed column names for sorting",
    checkFunction: "checkSQLiOrderBy"
  },
  {
    id: 231,
    category: "SQL Injection",
    title: "SQL Injection in LIMIT Clause",
    description: "User-controlled LIMIT values not properly validated",
    severity: "medium",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate and cast LIMIT values to integers",
    checkFunction: "checkSQLiLimit"
  },
  {
    id: 232,
    category: "SQL Injection",
    title: "SQL Injection via JSON Parameters",
    description: "JSON data used in SQL without proper escaping",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Parse JSON safely, use parameterized queries",
    checkFunction: "checkSQLiJSON"
  },
  {
    id: 233,
    category: "SQL Injection",
    title: "NoSQL Injection",
    description: "MongoDB or other NoSQL queries vulnerable to injection",
    severity: "high",
    cwe: "CWE-943",
    owasp: "A03:2021 - Injection",
    recommendation: "Use proper query methods, avoid $where with user input",
    checkFunction: "checkNoSQLInjection"
  },
  {
    id: 234,
    category: "SQL Injection",
    title: "ORM Injection",
    description: "ORM raw queries or unsafe methods with user input",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Use ORM's safe query methods, avoid raw SQL",
    checkFunction: "checkORMInjection"
  },
  {
    id: 235,
    category: "SQL Injection",
    title: "Stored Procedure SQL Injection",
    description: "Stored procedures vulnerable to injection",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Use parameters in stored procedures, avoid dynamic SQL",
    checkFunction: "checkStoredProcedureSQLi"
  },
  {
    id: 236,
    category: "SQL Injection",
    title: "SQL Injection in LIKE Clause",
    description: "LIKE patterns not properly escaped",
    severity: "medium",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Escape wildcards in LIKE patterns, use parameterized queries",
    checkFunction: "checkSQLiLike"
  },
  {
    id: 237,
    category: "SQL Injection",
    title: "GraphQL Injection",
    description: "GraphQL queries vulnerable to injection",
    severity: "high",
    cwe: "CWE-89",
    owasp: "A03:2021 - Injection",
    recommendation: "Use GraphQL libraries properly, parameterize database queries",
    checkFunction: "checkGraphQLInjection"
  },
  {
    id: 238,
    category: "SQL Injection",
    title: "LDAP Injection",
    description: "LDAP queries with unescaped user input",
    severity: "high",
    cwe: "CWE-90",
    owasp: "A03:2021 - Injection",
    recommendation: "Escape LDAP special characters in user input",
    checkFunction: "checkLDAPInjection"
  },
  {
    id: 239,
    category: "SQL Injection",
    title: "XML Injection",
    description: "XML data includes unescaped user input",
    severity: "medium",
    cwe: "CWE-91",
    owasp: "A03:2021 - Injection",
    recommendation: "Escape XML special characters, use XML libraries properly",
    checkFunction: "checkXMLInjection"
  },
  {
    id: 240,
    category: "SQL Injection",
    title: "XPath Injection",
    description: "XPath queries with user input not escaped",
    severity: "high",
    cwe: "CWE-643",
    owasp: "A03:2021 - Injection",
    recommendation: "Use parameterized XPath queries or escape input",
    checkFunction: "checkXPathInjection"
  },

  // Command Injection (41-55)
  {
    id: 241,
    category: "Command Injection",
    title: "OS Command Injection",
    description: "System commands executed with user input",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid system calls, use language libraries, validate input strictly",
    checkFunction: "checkCommandInjection"
  },
  {
    id: 242,
    category: "Command Injection",
    title: "Shell Injection via exec()",
    description: "exec() or shell_exec() with user data",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    recommendation: "Never pass user input to shell commands, use language-specific APIs",
    checkFunction: "checkShellExec"
  },
  {
    id: 243,
    category: "Command Injection",
    title: "Command Injection in File Operations",
    description: "File operations use shell commands with user input",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    recommendation: "Use language file APIs instead of shell commands",
    checkFunction: "checkFileCommandInjection"
  },
  {
    id: 244,
    category: "Command Injection",
    title: "Command Injection via System Calls",
    description: "system() or similar functions with untrusted data",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid system calls entirely, use safe alternatives",
    checkFunction: "checkSystemCalls"
  },
  {
    id: 245,
    category: "Command Injection",
    title: "Command Injection in Backticks",
    description: "Backtick execution with user input (PHP, Perl, Shell)",
    severity: "critical",
    cwe: "CWE-78",
    owasp: "A03:2021 - Injection",
    recommendation: "Never use backticks with user data",
    checkFunction: "checkBacktickInjection"
  },
  {
    id: 246,
    category: "Command Injection",
    title: "Python eval/exec Injection",
    description: "Python eval() or exec() with user input",
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Never use eval()/exec() with user input, use ast.literal_eval() for safe evaluation",
    checkFunction: "checkPythonEvalExec"
  },
  {
    id: 247,
    category: "Command Injection",
    title: "Code Injection via Deserialization",
    description: "Deserializing untrusted data leads to code execution",
    severity: "critical",
    cwe: "CWE-502",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    recommendation: "Avoid deserializing untrusted data, use JSON instead",
    checkFunction: "checkDeserializationInjection"
  },
  {
    id: 248,
    category: "Command Injection",
    title: "Ruby eval Injection",
    description: "Ruby eval with user-controlled strings",
    severity: "critical",
    cwe: "CWE-95",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid eval in Ruby, use safe alternatives",
    checkFunction: "checkRubyEval"
  },
  {
    id: 249,
    category: "Command Injection",
    title: "Expression Language Injection",
    description: "EL expressions with user input (Java, JSP)",
    severity: "high",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Sanitize input before EL evaluation, use safe expression contexts",
    checkFunction: "checkELInjection"
  },
  {
    id: 250,
    category: "Command Injection",
    title: "OGNL Injection",
    description: "Object-Graph Navigation Language injection (Struts)",
    severity: "critical",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Update Struts, avoid user input in OGNL expressions",
    checkFunction: "checkOGNLInjection"
  },
  {
    id: 251,
    category: "Command Injection",
    title: "SpEL Injection",
    description: "Spring Expression Language injection",
    severity: "critical",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid parsing user input as SpEL expressions",
    checkFunction: "checkSpELInjection"
  },
  {
    id: 252,
    category: "Command Injection",
    title: "SSTI - Server-Side Template Injection",
    description: "User input in server-side templates",
    severity: "critical",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Use safe template rendering, avoid user input in templates",
    checkFunction: "checkSSTI"
  },
  {
    id: 253,
    category: "Command Injection",
    title: "Remote Code Execution via File Upload",
    description: "Uploaded files executed as code",
    severity: "critical",
    cwe: "CWE-434",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate file types, store outside webroot, disable execution",
    checkFunction: "checkFileUploadRCE"
  },
  {
    id: 254,
    category: "Command Injection",
    title: "PHP Code Injection",
    description: "User input passed to PHP code execution functions",
    severity: "critical",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Never use eval(), assert(), create_function() with user input",
    checkFunction: "checkPHPCodeInjection"
  },
  {
    id: 255,
    category: "Command Injection",
    title: "Node.js VM Escape",
    description: "Node.js vm module used unsafely with user code",
    severity: "critical",
    cwe: "CWE-94",
    owasp: "A03:2021 - Injection",
    recommendation: "Avoid vm module with untrusted code, use isolated containers",
    checkFunction: "checkNodeVMEscape"
  },

  // CSRF (56-65)
  {
    id: 256,
    category: "CSRF",
    title: "Missing CSRF Token",
    description: "State-changing forms lack CSRF protection",
    severity: "high",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Implement CSRF tokens for all state-changing operations",
    checkFunction: "checkCSRFToken"
  },
  {
    id: 257,
    category: "CSRF",
    title: "CSRF Token Not Validated",
    description: "CSRF token present but not validated server-side",
    severity: "high",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Validate CSRF token on server for every request",
    checkFunction: "checkCSRFValidation"
  },
  {
    id: 258,
    category: "CSRF",
    title: "CSRF Token in GET Request",
    description: "CSRF token passed in URL parameters",
    severity: "high",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Send CSRF tokens in POST body or custom headers only",
    checkFunction: "checkCSRFInGET"
  },
  {
    id: 259,
    category: "CSRF",
    title: "CSRF Token Not Tied to Session",
    description: "CSRF token not bound to user session",
    severity: "high",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Generate unique CSRF token per session",
    checkFunction: "checkCSRFSessionBinding"
  },
  {
    id: 260,
    category: "CSRF",
    title: "CSRF Token Reusable",
    description: "Same CSRF token valid for extended period",
    severity: "medium",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Rotate CSRF tokens regularly or per-request",
    checkFunction: "checkCSRFReuse"
  },
  {
    id: 261,
    category: "CSRF",
    title: "State Change via GET",
    description: "GET requests perform state-changing operations",
    severity: "high",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Use POST, PUT, DELETE for state changes, never GET",
    checkFunction: "checkStateChangeGET"
  },
  {
    id: 262,
    category: "CSRF",
    title: "Missing SameSite Cookie Attribute",
    description: "Cookies lack SameSite attribute for CSRF protection",
    severity: "medium",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Set SameSite=Strict or Lax on cookies",
    checkFunction: "checkSameSiteCSRF"
  },
  {
    id: 263,
    category: "CSRF",
    title: "CSRF in API Endpoints",
    description: "REST API vulnerable to CSRF attacks",
    severity: "high",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Use custom headers, validate Origin/Referer for APIs",
    checkFunction: "checkAPICSRF"
  },
  {
    id: 264,
    category: "CSRF",
    title: "Login CSRF",
    description: "Login forms vulnerable to CSRF",
    severity: "medium",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Protect login forms with CSRF tokens",
    checkFunction: "checkLoginCSRF"
  },
  {
    id: 265,
    category: "CSRF",
    title: "Logout CSRF",
    description: "Logout can be triggered via CSRF",
    severity: "medium",
    cwe: "CWE-352",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Protect logout with CSRF token or use POST method",
    checkFunction: "checkLogoutCSRF"
  },

  // Input Validation (66-85)
  {
    id: 266,
    category: "Input Validation",
    title: "No Input Length Validation",
    description: "Input fields lack maximum length constraints",
    severity: "medium",
    cwe: "CWE-120",
    owasp: "A03:2021 - Injection",
    recommendation: "Implement maximum length validation for all inputs",
    checkFunction: "checkInputLength"
  },
  {
    id: 267,
    category: "Input Validation",
    title: "No Input Type Validation",
    description: "Input types not validated (string, number, email, etc.)",
    severity: "medium",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate input types match expected format",
    checkFunction: "checkInputType"
  },
  {
    id: 268,
    category: "Input Validation",
    title: "No Email Format Validation",
    description: "Email addresses accepted without format validation",
    severity: "low",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate email format using regex or validation library",
    checkFunction: "checkEmailValidation"
  },
  {
    id: 269,
    category: "Input Validation",
    title: "No URL Format Validation",
    description: "URLs accepted without validation",
    severity: "medium",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate URL format and scheme (http/https only)",
    checkFunction: "checkURLValidation"
  },
  {
    id: 270,
    category: "Input Validation",
    title: "Integer Overflow Not Checked",
    description: "Numeric inputs not checked for overflow",
    severity: "medium",
    cwe: "CWE-190",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate numeric ranges, use safe integer operations",
    checkFunction: "checkIntegerOverflow"
  },
  {
    id: 271,
    category: "Input Validation",
    title: "Negative Number Not Restricted",
    description: "Numeric fields accept negative values inappropriately",
    severity: "low",
    cwe: "CWE-20",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate numeric ranges, reject negative values where not allowed",
    checkFunction: "checkNegativeNumbers"
  },
  {
    id: 272,
    category: "Input Validation",
    title: "Client-Side Validation Only",
    description: "Validation performed only in JavaScript",
    severity: "high",
    cwe: "CWE-602",
    owasp: "A03:2021 - Injection",
    recommendation: "Always validate on server-side, client-side is supplementary",
    checkFunction: "checkClientSideValidation"
  },
  {
    id: 273,
    category: "Input Validation",
    title: "File Extension Validation Only",
    description: "File uploads validated by extension only",
    severity: "high",
    cwe: "CWE-434",
    owasp: "A03:2021 - Injection",
    recommendation: "Validate file content type and magic bytes, not just extension",
    checkFunction: "checkFileExtensionOnly"
  },
  {
    id: 274,
    category: "Input Validation",
    title: "No File Size Limit",
    description: "File uploads lack size restrictions",
    severity: "medium",
    cwe: "CWE-400",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Implement file size limits based on business needs",
    checkFunction: "checkFileSize Limit"
  },
  {
    id: 275,
    category: "Input Validation",
    title: "No File Type Whitelist",
    description: "Any file type can be uploaded",
    severity: "high",
    cwe: "CWE-434",
    owasp: "A03:2021 - Injection",
    recommendation: "Whitelist allowed file types, reject all others",
    checkFunction: "checkFileTypeWhitelist"
  },
  {
    id: 276,
    category: "Input Validation",
    title: "Path Traversal in Filename",
    description: "File upload names not sanitized for path traversal",
    severity: "critical",
    cwe: "CWE-22",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Sanitize filenames, remove ../ and absolute paths",
    checkFunction: "checkPathTraversal"
  },
  {
    id: 277,
    category: "Input Validation",
    title: "Null Byte Injection",
    description: "Inputs not protected against null byte injection",
    severity: "medium",
    cwe: "CWE-158",
    owasp: "A03:2021 - Injection",
    recommendation: "Strip null bytes from user input",
    checkFunction: "checkNullByteInjection"
  },
  {
    id: 278,
    category: "Input Validation",
    title: "Unicode Normalization Issues",
    description: "Unicode input not normalized before validation",
    severity: "medium",
    cwe: "CWE-176",
    owasp: "A03:2021 - Injection",
    recommendation: "Normalize Unicode strings before validation and processing",
    checkFunction: "checkUnicodeNormalization"
  },
  {
    id: 279,
    category: "Input Validation",
    title: "Homograph Attack Possible",
    description: "Lookalike Unicode characters not detected",
    severity: "medium",
    cwe: "CWE-1007",
    owasp: "A03:2021 - Injection",
    recommendation: "Detect and warn about mixed-script identifiers",
    checkFunction: "checkHomographAttack"
  },
  {
    id: 280,
    category: "Input Validation",
    title: "Regex Denial of Service (ReDoS)",
    description: "Regular expressions vulnerable to catastrophic backtracking",
    severity: "medium",
    cwe: "CWE-1333",
    owasp: "A04:2021 - Insecure Design",
    recommendation: "Use safe regex patterns, limit execution time",
    checkFunction: "checkReDoS"
  },
  {
    id: 281,
    category: "Input Validation",
    title: "Mass Assignment Vulnerability",
    description: "Object properties auto-bound without whitelist",
    severity: "high",
    cwe: "CWE-915",
    owasp: "A01:2021 - Broken Access Control",
    recommendation: "Whitelist allowed properties for mass assignment",
    checkFunction: "checkMassAssignment"
  },
  {
    id: 282,
    category: "Input Validation",
    title: "XML External Entity (XXE)",
    description: "XML parser processes external entities",
    severity: "critical",
    cwe: "CWE-611",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Disable external entity processing in XML parsers",
    checkFunction: "checkXXE"
  },
  {
    id: 283,
    category: "Input Validation",
    title: "XML Bomb (Billion Laughs)",
    description: "XML parser vulnerable to entity expansion attacks",
    severity: "high",
    cwe: "CWE-776",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Limit entity expansion in XML parsers",
    checkFunction: "checkXMLBomb"
  },
  {
    id: 284,
    category: "Input Validation",
    title: "JSON Injection",
    description: "User input inserted into JSON without proper escaping",
    severity: "high",
    cwe: "CWE-91",
    owasp: "A03:2021 - Injection",
    recommendation: "Use proper JSON encoding libraries, don't concatenate strings",
    checkFunction: "checkJSONInjection"
  },
  {
    id: 285,
    category: "Input Validation",
    title: "YAML Deserialization",
    description: "YAML deserialization without safe loading",
    severity: "critical",
    cwe: "CWE-502",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    recommendation: "Use safe_load() instead of load() for YAML",
    checkFunction: "checkYAMLDeserialization"
  },

  // Server-Side Request Forgery (86-100)
  {
    id: 286,
    category: "SSRF",
    title: "SSRF via URL Parameter",
    description: "Application fetches user-provided URLs",
    severity: "critical",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Validate URLs against whitelist, block internal IPs",
    checkFunction: "checkSSRF"
  },
  {
    id: 287,
    category: "SSRF",
    title: "SSRF to Internal Network",
    description: "No protection against accessing internal IPs",
    severity: "critical",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Block RFC1918 private IPs, localhost, link-local addresses",
    checkFunction: "checkSSRFInternal"
  },
  {
    id: 288,
    category: "SSRF",
    title: "SSRF via Redirect",
    description: "SSRF protection bypassed via HTTP redirects",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Validate all URLs in redirect chain",
    checkFunction: "checkSSRFRedirect"
  },
  {
    id: 289,
    category: "SSRF",
    title: "SSRF via DNS Rebinding",
    description: "DNS resolution allows bypass of IP restrictions",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Resolve DNS before and after connection, validate consistency",
    checkFunction: "checkDNSRebinding"
  },
  {
    id: 290,
    category: "SSRF",
    title: "SSRF to Cloud Metadata",
    description: "Can access cloud metadata services (169.254.169.254)",
    severity: "critical",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Block 169.254.169.254 and cloud metadata endpoints",
    checkFunction: "checkCloudMetadataSSRF"
  },
  {
    id: 291,
    category: "SSRF",
    title: "SSRF via File Protocol",
    description: "file:// protocol allowed in URL fetching",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Whitelist allowed protocols (http, https only)",
    checkFunction: "checkFileProtocolSSRF"
  },
  {
    id: 292,
    category: "SSRF",
    title: "SSRF via gopher Protocol",
    description: "gopher:// protocol allows protocol smuggling",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Block gopher:// and other unusual protocols",
    checkFunction: "checkGopherSSRF"
  },
  {
    id: 293,
    category: "SSRF",
    title: "Blind SSRF",
    description: "SSRF without response visibility",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Implement same protections as regular SSRF",
    checkFunction: "checkBlindSSRF"
  },
  {
    id: 294,
    category: "SSRF",
    title: "SSRF in PDF Generation",
    description: "PDF generators fetch external resources unsafely",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Disable external resource fetching or whitelist domains",
    checkFunction: "checkPDFSSRF"
  },
  {
    id: 295,
    category: "SSRF",
    title: "SSRF in Image Processing",
    description: "Image processors fetch from user-provided URLs",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Validate image URLs, use proxy service",
    checkFunction: "checkImageSSRF"
  },
  {
    id: 296,
    category: "SSRF",
    title: "SSRF in Webhook Endpoints",
    description: "Webhooks can target internal services",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Validate webhook URLs, block internal addresses",
    checkFunction: "checkWebhookSSRF"
  },
  {
    id: 297,
    category: "SSRF",
    title: "SSRF via XML External Entity",
    description: "XXE used to perform SSRF",
    severity: "critical",
    cwe: "CWE-611",
    owasp: "A05:2021 - Security Misconfiguration",
    recommendation: "Disable external entities in XML parsers",
    checkFunction: "checkXXESSRF"
  },
  {
    id: 298,
    category: "SSRF",
    title: "SSRF via SVG Files",
    description: "SVG uploads can trigger SSRF",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Sanitize SVG uploads, disable external resource loading",
    checkFunction: "checkSVGSSRF"
  },
  {
    id: 299,
    category: "SSRF",
    title: "SSRF in URL Preview",
    description: "URL preview features vulnerable to SSRF",
    severity: "high",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Implement URL validation and rate limiting",
    checkFunction: "checkURLPreviewSSRF"
  },
  {
    id: 300,
    category: "SSRF",
    title: "SSRF via Server-Side Analytics",
    description: "Analytics pixel/beacon requests exploitable",
    severity: "medium",
    cwe: "CWE-918",
    owasp: "A10:2021 - Server-Side Request Forgery",
    recommendation: "Validate tracking URLs, use whitelist",
    checkFunction: "checkAnalyticsSSRF"
  }
];

// Export for use in scanner
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { category3_InputValidationInjection };
}
