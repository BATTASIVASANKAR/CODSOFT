/**
 * SECURE CODE ASSESSMENT TOOL - SAST SECURITY RULE ENGINE
 * Comprehensive Security Rules Database for Static Analysis
 * Languages: Python (.py), JavaScript (.js), Java (.java), C/C++ (.cpp), PHP (.php)
 */

window.SAST_RULES = [
  // ==========================================
  // 1. HARDCODED CREDENTIALS & SECRETS
  // ==========================================
  {
    id: "RULE_HARDCODED_SECRET_01",
    name: "Hardcoded API Key or Token",
    category: "Hardcoded Credentials",
    owasp: "A07:2021 - Identification and Authentication Failures",
    severity: "CRITICAL",
    languages: ["py", "js", "java", "cpp", "php"],
    pattern: /(?:api_key|apikey|secret_key|jwt_secret|api_secret|access_token)\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]/i,
    description: "Hardcoded API keys, JWT secrets, or tokens detected in source code. Storing credentials in plain text leads to unauthorized access if source code is exposed.",
    risk: "Attacker with access to repository can authenticate as administrative services or compromise cloud infrastructure.",
    remediation: "Move sensitive credentials to environment variables or dedicated secret management vaults (e.g., AWS Secrets Manager, HashiCorp Vault).",
    secureExample: "const API_KEY = process.env.API_KEY;\n# Python: api_key = os.environ.get('API_KEY')"
  },
  {
    id: "RULE_HARDCODED_PASS_02",
    name: "Hardcoded Database or User Password",
    category: "Hardcoded Credentials",
    owasp: "A07:2021 - Identification and Authentication Failures",
    severity: "CRITICAL",
    languages: ["py", "js", "java", "cpp", "php"],
    pattern: /(?:db_pass|database_password|DB_PASSWORD|DB_PASS|pass|password)\s*=\s*['"][^'"]{4,}['"]/i,
    description: "Hardcoded plain-text password found in variable assignment.",
    risk: "Exposes database credentials to anyone with code repository access, risking complete data breach.",
    remediation: "Inject credentials via environment variables or secure key vaults during deployment.",
    secureExample: "DB_PASS = os.getenv('DATABASE_PASSWORD')"
  },

  // ==========================================
  // 2. SQL INJECTION (SQLi)
  // ==========================================
  {
    id: "RULE_SQLI_STRING_CONCAT",
    name: "SQL Injection via String Concatenation",
    category: "SQL Injection",
    owasp: "A03:2021 - Injection",
    severity: "CRITICAL",
    languages: ["py", "js", "java", "cpp", "php"],
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\+.*?\$?[A-Za-z0-9_]+|(?:f['"].*?SELECT.*?\{[A-Za-z0-9_]+\}|query\s*=\s*["'].*?SELECT.*?["']\s*\.\s*\$[A-Za-z0-9_]+)/i,
    description: "Dynamic SQL query constructed using string concatenation or unescaped string formatting with user inputs.",
    risk: "Allows attackers to manipulate SQL commands, bypass authentication, read sensitive data, or drop database tables.",
    remediation: "Use parameterized queries (Prepared Statements) or an Object-Relational Mapper (ORM).",
    secureExample: "// JavaScript:\ndb.query('SELECT * FROM users WHERE id = ?', [userId]);\n# Python:\ncursor.execute('SELECT * FROM users WHERE id = %s', (userId,))"
  },
  {
    id: "RULE_SQLI_RAW_EXEC",
    name: "Raw SQL Execution on Unsanitized Statement",
    category: "SQL Injection",
    owasp: "A03:2021 - Injection",
    severity: "HIGH",
    languages: ["py", "java", "php"],
    pattern: /(?:stmt\.executeQuery|cursor\.execute|mysqli_query)\s*\(\s*["']?.*?['"]?\s*\+\s*[A-Za-z0-9_]+\s*\)/i,
    description: "Executing unparameterized SQL query statement directly via raw database cursor.",
    risk: "Direct SQL injection leading to remote data exfiltration or modification.",
    remediation: "Bind parameters explicitly instead of embedding variables in the SQL string.",
    secureExample: "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE user = ?\");\nstmt.setString(1, username);"
  },

  // ==========================================
  // 3. CROSS-SITE SCRIPTING (XSS)
  // ==========================================
  {
    id: "RULE_XSS_INNER_HTML",
    name: "DOM Cross-Site Scripting (innerHTML)",
    category: "Cross-Site Scripting",
    owasp: "A03:2021 - Injection",
    severity: "HIGH",
    languages: ["js"],
    pattern: /\.innerHTML\s*=\s*.*?(?:req\.|params|body|input|location|document\.)/i,
    description: "Assigning unescaped user input directly to element.innerHTML.",
    risk: "Executes malicious scripts in the victim's browser, allowing session hijacking or cookie theft.",
    remediation: "Use element.textContent or sanitize user inputs using DOMPurify before rendering.",
    secureExample: "element.textContent = userInput;\n// Or sanitized:\nelement.innerHTML = DOMPurify.sanitize(userInput);"
  },
  {
    id: "RULE_XSS_UNESCAPED_TEMPLATE",
    name: "Unsanitized Template Rendering",
    category: "Cross-Site Scripting",
    owasp: "A03:2021 - Injection",
    severity: "HIGH",
    languages: ["py", "php"],
    pattern: /(?:render_template_string\s*\(.*?\$?[A-Za-z0-9_]+\)|echo\s+["']<.*?["']\s*\.\s*\$_(?:GET|POST|REQUEST))/i,
    description: "Direct output of unescaped HTTP parameters into HTML markup.",
    risk: "Reflected Cross-Site Scripting (XSS) targeting application visitors.",
    remediation: "Use htmlspecialchars() in PHP or Jinja2 template auto-escaping in Python Flask.",
    secureExample: "echo htmlspecialchars($_POST['comment'], ENT_QUOTES, 'UTF-8');"
  },

  // ==========================================
  // 4. COMMAND INJECTION
  // ==========================================
  {
    id: "RULE_CMD_INJECTION_OS",
    name: "OS Command Injection",
    category: "Command Injection",
    owasp: "A03:2021 - Injection",
    severity: "CRITICAL",
    languages: ["py", "js", "java", "cpp", "php"],
    pattern: /(?:os\.system|child_process\.exec|Runtime\.getRuntime\(\)\.exec|system\s*\(|passthru\s*\()\s*\(.*?(?:\+|f['"]|\.|\$)[A-Za-z0-9_]+/i,
    description: "System command executed with concatenated user-supplied arguments without validation.",
    risk: "Remote Code Execution (RCE), giving attackers complete shell access to the host server.",
    remediation: "Avoid system calls. If required, pass arguments as an array without invoking shell interpreters (`shell=False`).",
    secureExample: "# Python:\nsubprocess.run(['ping', '-c', '1', host], shell=False)"
  },

  // ==========================================
  // 5. WEAK AUTHENTICATION & CRYPTOGRAPHY
  // ==========================================
  {
    id: "RULE_WEAK_HASH_MD5_SHA1",
    name: "Use of Weak Hashing Algorithm (MD5 / SHA1)",
    category: "Weak Authentication",
    owasp: "A02:2021 - Cryptographic Failures",
    severity: "HIGH",
    languages: ["py", "js", "java", "php"],
    pattern: /(?:hashlib\.md5|hashlib\.sha1|crypto\.createHash\(['"]md5['"]\)|crypto\.createHash\(['"]sha1['"]\)|MessageDigest\.getInstance\(['"](?:MD5|SHA-1)['"]\)|md5\s*\(|sha1\s*\()/i,
    description: "MD5 and SHA-1 algorithms are cryptographically broken and vulnerable to collision attacks.",
    risk: "Attackers can reverse password hashes quickly using rainbow tables or hash collisions.",
    remediation: "Use Argon2id, bcrypt, or PBKDF2 for password hashing.",
    secureExample: "# Python:\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())"
  },

  // ==========================================
  // 6. MISSING INPUT VALIDATION & DANGEROUS EVAL
  // ==========================================
  {
    id: "RULE_DANGEROUS_EVAL",
    name: "Use of Dangerous eval() Function",
    category: "Missing Input Validation",
    owasp: "A03:2021 - Injection",
    severity: "CRITICAL",
    languages: ["js", "py", "php"],
    pattern: /\beval\s*\(.*?\)/i,
    description: "eval() executes arbitrary strings as code in the current runtime scope.",
    risk: "Execution of arbitrary code leading to complete system compromise.",
    remediation: "Refactor code to parse structured formats like JSON.parse() instead of using eval().",
    secureExample: "const data = JSON.parse(jsonString);"
  },
  {
    id: "RULE_UNSAFE_DESERIALIZATION",
    name: "Unsafe Object Deserialization",
    category: "Missing Input Validation",
    owasp: "A08:2021 - Software and Data Integrity Failures",
    severity: "HIGH",
    languages: ["py", "php"],
    pattern: /(?:pickle\.loads|unserialize\s*\()/i,
    description: "Deserializing untrusted data without validation.",
    risk: "Object injection leading to Remote Code Execution (RCE).",
    remediation: "Use safe data serialization formats like JSON or safe_load() for YAML.",
    secureExample: "import json\ndata = json.loads(user_input)"
  },

  // ==========================================
  // 7. INSECURE FILE HANDLING & PATH TRAVERSAL
  // ==========================================
  {
    id: "RULE_PATH_TRAVERSAL",
    name: "Path Traversal / Arbitrary File Inclusion",
    category: "Insecure File Handling",
    owasp: "A01:2021 - Broken Access Control",
    severity: "HIGH",
    languages: ["py", "js", "java", "php"],
    pattern: /(?:open\s*\(\s*.*?\$?(?:req|filename|file|GET|POST)|include\s*\(\s*.*?\$_(?:GET|POST)|file_get_contents\s*\(\s*.*?\$_(?:GET|POST))/i,
    description: "File paths dynamically derived from unvalidated user input.",
    risk: "Allows attackers to access sensitive server files like /etc/passwd or configuration files.",
    remediation: "Sanitize paths using whitelist checks or path resolving (e.g. path.basename()).",
    secureExample: "$allowed = ['home.php', 'about.php'];\nif (in_array($page, $allowed)) include($page);"
  },

  // ==========================================
  // 8. SENSITIVE INFORMATION EXPOSURE & MISCONFIGURATION
  // ==========================================
  {
    id: "RULE_DEBUG_MODE_ENABLED",
    name: "Debug Mode Enabled in Production",
    category: "Sensitive Info Exposure",
    owasp: "A05:2021 - Security Misconfiguration",
    severity: "MEDIUM",
    languages: ["py"],
    pattern: /app\.run\s*\(.*?debug\s*=\s*True/i,
    description: "Flask or Framework debug mode is explicitly set to True.",
    risk: "Exposes interactive debugger console and detailed stack traces to external users.",
    remediation: "Ensure debug mode is disabled in production environments.",
    secureExample: "app.run(debug=False)"
  },
  {
    id: "RULE_DISABLED_SSL_VERIFICATION",
    name: "Disabled TLS / SSL Certificate Verification",
    category: "Sensitive Info Exposure",
    owasp: "A02:2021 - Cryptographic Failures",
    severity: "HIGH",
    languages: ["py", "js"],
    pattern: /(?:verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?)/i,
    description: "TLS certificate validation disabled during HTTP communication.",
    risk: "Exposes application network traffic to Man-in-the-Middle (MitM) interception attacks.",
    remediation: "Always enable TLS certificate validation in production requests.",
    secureExample: "response = requests.get('https://api.example.com', verify=True)"
  },
  {
    id: "RULE_SENSITIVE_LOGGING",
    name: "Sensitive Data Logged to Console",
    category: "Sensitive Info Exposure",
    owasp: "A09:2021 - Security Logging and Monitoring Failures",
    severity: "LOW",
    languages: ["js", "py", "java"],
    pattern: /(?:console\.log|print|System\.out\.println)\s*\(.*?(?:password|pass|auth_token|token|credit_card|ssn)/i,
    description: "Logging sensitive credentials or tokens to standard application logs.",
    risk: "Exposes sensitive credentials in log management systems or server stdout.",
    remediation: "Mask or redact sensitive fields before writing to logs.",
    secureExample: "console.log('User login attempt:', { username: user.name, password: '***' });"
  }
];
