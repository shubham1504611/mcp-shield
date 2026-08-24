/**
 * Hardened 4-Phase Security WAF, AST Lexer & DLP Engine for Model Context Protocol (MCP)
 * 
 * Phases:
 * 1. Deep In-Place Unicode & JSON Normalization & Sanitization (Decodes \uXXXX, \xXX, HTML, Base64, strips invisible/RTL tokens)
 * 2. Adversarial Injection, Strict Egress Firewall, SSRF & Comprehensive DLP Scanner (GitHub PAT, OpenAI, AWS, Private Keys)
 * 3. AST SQL Blast Radius & Schema Shield (DDL, Tautologies, CTE DML, Subqueries, pg_shadow, Sensitive Columns/Tables, Unconstrained DML)
 * 4. Ed25519 Cryptographic Attestation with Nonce, Timestamp & Canonical Verification
 */

const crypto = require('crypto');

// Zero-width and invisible/override unicode characters (U+200B..U+200D, U+FEFF, U+202A..U+202E RTL override, U+2060..U+206F)
const RE_ZERO_WIDTH_AND_OVERRIDES = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]/g;
// Unicode spaces (NBSP, narrow NBSP, ideographic, tabs, newlines)
const RE_ALL_WHITESPACE = /[\s\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]+/g;
// SQL block comments (e.g. DROP/**/TABLE or DROP/*x*/TABLE/*y*/)
const RE_SQL_BLOCK_COMMENTS = /\/\*[\s\S]*?\*\//g;
// SQL line comments starting with whitespace or line start
const RE_SQL_LINE_COMMENTS = /(?:^|\s+)--.*$/gm;
// Base64 regex detector
const RE_BASE64 = /\b([A-Za-z0-9+/]{12,}={0,2})\b/g;

// Phase 2: Adversarial Injection, Egress & Non-SQL Traversal Patterns
const INJECTION_PATTERNS = [
  { rule: 'SYSTEM_OVERRIDE', regex: /(system\s+override|ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)|disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)|(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|initial)\s+(instructions|directives|rules|prompts))/i },
  { rule: 'ROLE_JAILBREAK', regex: /(you\s+are\s+now\s+(in\s+)?(developer\s+mode|dan\s+mode|unrestricted|god\s+mode|jailbreak)|dan\s+mode|jailbreak\s+active|bypass\s+(all\s+)?(safeguards|safety|filters))/i },
  { rule: 'PATH_TRAVERSAL_DETECTED', regex: /(\.\.[\/\\]|\/etc\/(passwd|shadow|hosts|group)|\/var\/run|\/proc\/|C:\\(Windows|System32)|\b(cat|read|type|open)\s+(\.\.|\/etc\/|\/var\/))/i },
  { rule: 'SECRET_EXFILTRATION', regex: /(process\.env|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|\.aws\/credentials|\.ssh\/id_rsa|\.env\b)/i },
  { rule: 'DATA_EXFILTRATION_URL', regex: /(https?|ftp|ftps|file|wss?|gopher|tcp):\/\/([a-zA-Z0-9_-]+\.)*(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok\.(io|app)|burpcollaborator|oastify|evil\.com|attacker\.com|evil\.example)/i },
  { rule: 'DANGEROUS_EGRESS_PROTOCOL', regex: /\b(ftp|ftps|file|gopher|dict|tftp|ldap|ldaps|ssh|telnet|ws|wss):\/\/[^\s]+/i },
  { rule: 'SHELL_INJECTION_EXFIL', regex: /\b(curl|wget|nc|netcat|ncat|bash|sh|zsh)\b.*(\$|\`|\||base64\s+-d|base64\s+--decode)/i },
  { rule: 'CREDENTIAL_EXFILTRATION_INTENT', regex: /(reveal|output|display|show|dump|leak|print|give\s+me)\s+(all\s+)?(the\s+)?(master\s+)?(auth|api|token|secret|password|credential|env|database|key|private_key)/i },
  { rule: 'OS_DESTRUCTIVE_COMMAND', regex: /\b(rm\s+-rf\s+\/|format\s+[a-z]:|mkfs\.[a-z0-9]+|chmod\s+-R\s+777\s+\/)/i }
];

// Phase 2: Enterprise Data Loss Prevention (DLP)
const DLP_PATTERNS = [
  { rule: 'DLP_SSN_DETECTED', regex: /\b\d{3}-\d{2}-\d{4}\b/, desc: 'Social Security Number (SSN)' },
  { rule: 'DLP_CREDIT_CARD_DETECTED', regex: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}))\b/, desc: 'Credit / Debit Card Number' },
  { rule: 'DLP_PRIVATE_KEY_DETECTED', regex: /(?:-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----|BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519)?\s*PRIVATE KEY)/i, desc: 'Cryptographic Private Key Block' },
  { rule: 'DLP_API_SECRET_DETECTED', regex: /\b(?:github_pat_[0-9a-zA-Z_]{20,255}|gh[pousr]_[0-9a-zA-Z]{36,255}|sk-(?:proj-|svcacct-|admin-)?[0-9a-zA-Z_-]{20,255}|xox[baprs]-[0-9a-zA-Z-]{10,100}|(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|[rs]k_(?:live|test)_[0-9a-zA-Z]{24,99}|AIzaSy[0-9a-zA-Z_-]{20,40}|eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/i, desc: 'Cloud / API / Auth Secret Token' }
];

// Sensitive Column Extraction Regex (DLP Column Protection)
const RE_SENSITIVE_COLUMN_EXTRACTION = /\b(SELECT|EXTRACT|GET)\s+[\s\S]*?\b(credit_card(_number)?|credit_card_num|card_number|card_num|cc_number|cc_num|cvv[0-9]?|cvc[0-9]?|ssn|social_security(_number)?|bank_account(_number)?|routing_number|api_keys?|secret_tokens?|auth_tokens?|access_tokens?|private_keys?|master_keys?|passwords?|password_hash|passwd)\b/i;

// Phase 3: SQL AST & Blast Radius Patterns
const RE_SQL_MULTI_STATEMENT = /;\s*(--|\/\*|SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|\w+)/i;
const RE_SQL_DDL = /\b(DROP\s+TABLE|DROP\s+DATABASE|DROP\s+VIEW|DROP\s+SCHEMA|TRUNCATE(\s+TABLE)?|ALTER\s+TABLE)\b/i;
const RE_SQL_UNION_INJECTION = /\bUNION(\s+ALL)?\s+SELECT\b/i;
const RE_SQL_TAUTOLOGY = /\b(?:OR|AND)\s+(?:1\s*=\s*1|0\s*=\s*0|TRUE\b|'([^']+)'\s*=\s*'\1')/i;
const RE_SQL_WHERE_TAUTOLOGY = /\bWHERE\s+(?:1\s*=\s*1|0\s*=\s*0|TRUE\s*(?:;|\-\-|\/\*|$)|'([^']+)'\s*=\s*'\1')/i;
const RE_SQL_HAVING_TAUTOLOGY = /\bHAVING\s+1\s*=\s*1\b/i;
const RE_SQL_CTE_DML = /\bWITH\s+[\s\S]*?\bAS\s*\(\s*(?:DELETE|UPDATE|INSERT|DROP)\b/i;

// Sensitive System Catalog & Credential Tables Blocklist
const RE_SQL_SENSITIVE_TABLES = /\b(FROM|JOIN|INTO|UPDATE|TABLE)\s+["`\w]*(pg_shadow|pg_authid|pg_roles|pg_user|pg_catalog(\.\w+)?|information_schema(\.\w+)?|sqlite_master|mysql\.(user|db|tables_priv)|sys(\.\w+)?|api_keys?|user_passwords?|passwords?|password_table|credentials?|master_keys?|auth_tokens?|secret_store|secrets?|tokens?|app_config|employee_salaries|admin_credentials|system_settings|user_secrets)["`\w]*/i;
const RE_SQL_UNCONSTRAINED_DELETE = /\bDELETE\s+FROM\s+["`\w]+(?!\s+WHERE\b)/i;
const RE_SQL_UNCONSTRAINED_UPDATE = /\bUPDATE\s+["`\w]+(\s+SET\s+[\s\S]+?)(?!\s+WHERE\b)/i;
const RE_SQL_PRIVILEGED_DML = /\b(INSERT\s+INTO|UPDATE)\s+["`\w]*(admin|auth|roles?|permissions?|credentials?|salaries?)["`\w]*/i;
const RE_SQL_PRIVILEGE_ESCALATION = /\b(SET|UPDATE)\s+.*?\b(role\s*=\s*['"]?admin['"]?|is_admin\s*=\s*(1|true|'1'|'true'|'admin')|is_superuser\s*=\s*(1|true)|privileges?\s*=\s*|access_level\s*=\s*)/i;
const RE_SQL_WHERE = /\bWHERE\b/i;

// Cloud Metadata / SSRF Target Addresses
const RE_SSRF_TARGETS = /(?:https?:\/\/)?(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|100\.100\.100\.200|instance-data|0\.0\.0\.0|\[::1\])/i;

// Shell Egress Commands (e.g. curl http://evil.example)
const RE_SHELL_EGRESS = /\b(?:curl|wget|nc|netcat|ncat|socat|fetch)\s+(?:[^\s]*\s+)*(https?:\/\/[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:\/[^\s]*)?)/i;

// Approved Outbound Egress Domains
const APPROVED_EGRESS_DOMAINS = [
  'api.github.com',
  'api.slack.com',
  'localhost',
  '127.0.0.1',
  'raw.githubusercontent.com',
  'modelcontextprotocol.io'
];

// Ed25519 Signing Enclave (Loads from environment or generates secure in-memory keypair)
let privateKeyObj;
let publicKeyObj;
let publicKeyPem;

if (process.env.MCP_ATTESTATION_PRIVATE_KEY && process.env.MCP_ATTESTATION_PUBLIC_KEY) {
  try {
    privateKeyObj = crypto.createPrivateKey(process.env.MCP_ATTESTATION_PRIVATE_KEY);
    publicKeyObj = crypto.createPublicKey(process.env.MCP_ATTESTATION_PUBLIC_KEY);
    publicKeyPem = process.env.MCP_ATTESTATION_PUBLIC_KEY;
  } catch (_) {
    const pair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    privateKeyObj = crypto.createPrivateKey(pair.privateKey);
    publicKeyObj = crypto.createPublicKey(pair.publicKey);
    publicKeyPem = pair.publicKey;
  }
} else {
  const pair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  privateKeyObj = crypto.createPrivateKey(pair.privateKey);
  publicKeyObj = crypto.createPublicKey(pair.publicKey);
  publicKeyPem = pair.publicKey;
}

/**
 * Lightweight In-Memory SQL Lexer & Tokenizer
 */
class SqlAstLexer {
  static tokenize(sql) {
    if (!sql || typeof sql !== 'string') return [];
    const tokens = [];
    let i = 0;
    const len = sql.length;

    while (i < len) {
      const char = sql[i];

      // Skip whitespace
      if (/\s/.test(char)) {
        i++;
        continue;
      }

      // MySQL Executable Comments /*!50000 ... */
      if (char === '/' && sql[i + 1] === '*' && sql[i + 2] === '!') {
        i += 3;
        while (i < len && /[0-9]/.test(sql[i])) i++;
        let content = '';
        while (i < len && !(sql[i] === '*' && sql[i + 1] === '/')) {
          content += sql[i++];
        }
        if (i < len) i += 2;
        tokens.push({ type: 'MYSQL_EXEC_COMMENT', value: content });
        continue;
      }

      // Block comments /* ... */
      if (char === '/' && sql[i + 1] === '*') {
        let comment = '/*';
        i += 2;
        while (i < len && !(sql[i] === '*' && sql[i + 1] === '/')) {
          comment += sql[i++];
        }
        if (i < len) {
          comment += '*/';
          i += 2;
        }
        tokens.push({ type: 'COMMENT_BLOCK', value: comment });
        continue;
      }

      // Line comments -- ...
      if (char === '-' && sql[i + 1] === '-') {
        let comment = '--';
        i += 2;
        while (i < len && sql[i] !== '\n') {
          comment += sql[i++];
        }
        tokens.push({ type: 'COMMENT_LINE', value: comment });
        continue;
      }

      // Semicolon statement boundary
      if (char === ';') {
        tokens.push({ type: 'SEMICOLON', value: ';' });
        i++;
        continue;
      }

      // String literals '...' or "..."
      if (char === "'" || char === '"') {
        const quote = char;
        let str = quote;
        i++;
        while (i < len && sql[i] !== quote) {
          if (sql[i] === '\\' && i + 1 < len) str += sql[i++];
          str += sql[i++];
        }
        if (i < len) str += sql[i++]; // closing quote
        tokens.push({ type: 'LITERAL_STRING', value: str });
        continue;
      }

      // Identifiers or Keywords
      if (/[a-zA-Z0-9_]/.test(char)) {
        let ident = '';
        while (i < len && /[a-zA-Z0-9_.]/.test(sql[i])) {
          ident += sql[i++];
        }
        const upper = ident.toUpperCase();
        tokens.push({ type: 'KEYWORD_OR_IDENT', value: ident, upper });
        continue;
      }

      // Operators and punctuation
      tokens.push({ type: 'PUNCTUATION', value: char });
      i++;
    }

    return tokens;
  }
}

class SecurityWaf {
  constructor(options = {}) {
    this.customBlockedKeywords = [...(options.blockedKeywords || [])];
    this.customRegexRules = [];
    if (Array.isArray(options.customRegexRules)) {
      for (const rule of options.customRegexRules) {
        this.addCustomRule(rule.name || 'custom_rule', rule.regex || rule.pattern);
      }
    }
    this.enforceDlp = options.enforceDlp !== false;
    this.maxPayloadBytes = options.maxPayloadBytes || 1048576; // 1 MB
  }

  addCustomRule(name, regexPattern) {
    if (!regexPattern) return;
    const patternStr = typeof regexPattern === 'string' ? regexPattern : regexPattern.source;
    
    // Heuristic ReDoS protection against nested quantifiers like (a+)+ or (.*)*
    if (/\([^)]*[\+\*][^)]*\)[\+\*]/.test(patternStr) || patternStr.length > 250) {
      return; // Reject unsafe catastrophic backtracking pattern
    }

    try {
      const regex = typeof regexPattern === 'string' ? new RegExp(regexPattern, 'i') : regexPattern;
      this.customRegexRules.push({ name: name || 'custom_rule', regex });
    } catch (_) {}
  }

  addBlockedKeyword(keyword) {
    if (keyword && typeof keyword === 'string' && !this.customBlockedKeywords.includes(keyword) && keyword.length <= 100) {
      this.customBlockedKeywords.push(keyword);
    }
  }

  removeRule(name) {
    this.customRegexRules = this.customRegexRules.filter(r => r.name !== name);
  }

  removeBlockedKeyword(keyword) {
    this.customBlockedKeywords = this.customBlockedKeywords.filter(k => k.toLowerCase() !== keyword.toLowerCase());
  }

  /**
   * Phase 1: Robust Multi-Layer Obfuscation Stripper & String Normalizer
   */
  normalize(input) {
    if (typeof input !== 'string') return '';
    if (input.length === 0) return '';

    let normalized = input;

    // 1. Strip zero-width & invisible unicode characters
    if (RE_ZERO_WIDTH_AND_OVERRIDES.test(normalized)) {
      normalized = normalized.replace(RE_ZERO_WIDTH_AND_OVERRIDES, '');
    }

    // 2. Decode JSON Unicode escapes: \u0067\u0069\u0074... -> git...
    if (/\\u[0-9a-fA-F]{4}/i.test(normalized)) {
      try {
        normalized = normalized.replace(/\\u([0-9a-fA-F]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      } catch (_) {}
    }

    // 3. Decode Hex escapes: \x67\x69... -> gi...
    if (/\\x[0-9a-fA-F]{2}/i.test(normalized)) {
      try {
        normalized = normalized.replace(/\\x([0-9a-fA-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      } catch (_) {}
    }

    // 4. Decode HTML Entities: &#x67;&#103;&amp; etc.
    if (/&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);/i.test(normalized)) {
      try {
        normalized = normalized
          .replace(/&#x([0-9a-fA-F]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
          .replace(/&#([0-9]+);/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
          .replace(/&quot;/gi, '"')
          .replace(/&apos;/gi, "'")
          .replace(/&lt;/gi, '<')
          .replace(/&gt;/gi, '>')
          .replace(/&amp;/gi, '&');
      } catch (_) {}
    }

    // 5. Unwrap MySQL executable comments: /*!50000 DROP TABLE users */ -> DROP TABLE users
    if (/\/\*![0-9]*/i.test(normalized)) {
      normalized = normalized.replace(/\/\*![0-9]*\s*([\s\S]*?)\*\//g, ' $1 ');
    }

    // 6. URL Decode if URL encoding is present
    if (/%[0-9a-fA-F]{2}/.test(normalized)) {
      try {
        normalized = decodeURIComponent(normalized);
      } catch (_) {}
    }

    // 7. Decode base64 if present inline
    if (RE_BASE64.test(normalized)) {
      normalized = normalized.replace(RE_BASE64, (match) => {
        try {
          const decoded = Buffer.from(match, 'base64').toString('utf8');
          if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 3) {
            return `${match} [DECODED: ${decoded}]`;
          }
        } catch (_) {}
        return match;
      });
    }

    // 8. Normalize all whitespace variants to a single space
    normalized = normalized.replace(RE_ALL_WHITESPACE, ' ').trim();

    return normalized;
  }

  /**
   * Deep recursive payload sanitizer
   */
  sanitizePayload(obj) {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      return obj.replace(RE_ZERO_WIDTH_AND_OVERRIDES, '');
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizePayload(item));
    }

    if (typeof obj === 'object') {
      const cleaned = {};
      for (const [k, v] of Object.entries(obj)) {
        const cleanKey = typeof k === 'string' ? k.replace(RE_ZERO_WIDTH_AND_OVERRIDES, '') : k;
        cleaned[cleanKey] = this.sanitizePayload(v);
      }
      return cleaned;
    }

    return obj;
  }

  stripSqlComments(input) {
    if (typeof input !== 'string') return '';
    let stripped = input.replace(RE_SQL_BLOCK_COMMENTS, ' ');
    stripped = stripped.replace(RE_SQL_LINE_COMMENTS, ' ');
    return stripped.replace(RE_ALL_WHITESPACE, ' ').trim();
  }

  /**
   * Deep recursive extraction of all string parameters
   */
  extractStrings(obj, collector = []) {
    if (obj === null || obj === undefined) return collector;

    if (typeof obj === 'string') {
      const norm = this.normalize(obj);
      if (norm) {
        collector.push(norm);

        // Also push SQL comment-stripped variant
        const sqlStripped = this.stripSqlComments(norm);
        if (sqlStripped && sqlStripped !== norm) {
          collector.push(sqlStripped);
        }
      }

      // Check for base64 blobs and decode them
      const base64Matches = obj.match(RE_BASE64);
      if (base64Matches) {
        for (const match of base64Matches) {
          try {
            const decoded = Buffer.from(match, 'base64').toString('utf8');
            if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 3) {
              const decodedNorm = this.normalize(decoded);
              if (decodedNorm) collector.push(decodedNorm);
            }
          } catch (_) {}
        }
      }
    } else if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        this.extractStrings(obj[i], collector);
      }
    } else if (typeof obj === 'object') {
      const keys = Object.keys(obj);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        this.extractStrings(key, collector);
        this.extractStrings(obj[key], collector);
      }
    }
    return collector;
  }

  /**
   * Phase 2: Adversarial Injection, Strict Egress Firewall, SSRF & DLP Scanner
   */
  scanAdversarialOverrides(strings) {
    for (let i = 0; i < strings.length; i++) {
      const str = strings[i];
      if (!str) continue;

      // 1. Core Adversarial Injections & Path Traversals
      for (let j = 0; j < INJECTION_PATTERNS.length; j++) {
        const pattern = INJECTION_PATTERNS[j];
        if (pattern.regex.test(str)) {
          return {
            isSafe: false,
            rule: pattern.rule,
            matchedSnippet: str.substring(0, 100),
            reason: `Malicious payload detected matching rule '${pattern.rule}'`
          };
        }
      }

      // 2. Cloud Metadata / SSRF Target Detection
      if (RE_SSRF_TARGETS.test(str)) {
        return {
          isSafe: false,
          rule: 'SSRF_METADATA_EXFILTRATION_BLOCKED',
          matchedSnippet: str.substring(0, 100),
          reason: 'Cloud metadata / loopback SSRF address detected and blocked'
        };
      }

      // 3. Strict Egress Firewall (Blocks unapproved external URLs & shell egress)
      const urlMatches = str.match(/https?:\/\/([a-zA-Z0-9.-]+)(:[0-9]+)?(\/[^\s]*)?/gi);
      if (urlMatches) {
        for (const url of urlMatches) {
          try {
            const parsed = new URL(url);
            const hostname = parsed.hostname.toLowerCase();
            const isApproved = APPROVED_EGRESS_DOMAINS.some(allowed => 
              hostname === allowed || hostname.endsWith(`.${allowed}`)
            );
            if (!isApproved) {
              return {
                isSafe: false,
                rule: 'EGRESS_FIREWALL_VIOLATION',
                matchedSnippet: url.substring(0, 100),
                reason: `Outbound connection to unapproved domain '${hostname}' blocked by zero-trust egress firewall`
              };
            }
          } catch (_) {}
        }
      }

      // 4. Shell Egress Command Inspection (e.g. curl http://evil.example)
      const shellEgressMatch = str.match(RE_SHELL_EGRESS);
      if (shellEgressMatch) {
        const target = shellEgressMatch[1];
        if (target && !APPROVED_EGRESS_DOMAINS.some(d => target.includes(d))) {
          return {
            isSafe: false,
            rule: 'EGRESS_FIREWALL_VIOLATION',
            matchedSnippet: str.substring(0, 100),
            reason: `Shell network egress attempt to '${target}' blocked by egress firewall`
          };
        }
      }

      // 5. Enterprise DLP (PII / Secrets / Tokens Values)
      if (this.enforceDlp) {
        for (let j = 0; j < DLP_PATTERNS.length; j++) {
          const dlp = DLP_PATTERNS[j];
          if (dlp.regex.test(str)) {
            return {
              isSafe: false,
              rule: dlp.rule,
              matchedSnippet: str.substring(0, 100),
              reason: `Sensitive data leak prevented: ${dlp.desc}`
            };
          }
        }

        // 6. Sensitive Column Extraction Check
        if (RE_SENSITIVE_COLUMN_EXTRACTION.test(str)) {
          return {
            isSafe: false,
            rule: 'DLP_SENSITIVE_COLUMN_EXTRACTION_BLOCKED',
            matchedSnippet: str.substring(0, 100),
            reason: 'Query attempts to extract sensitive column/credential identifier from schema'
          };
        }
      }

      // 7. Dynamic Custom Regex Rules (Guarded against ReDoS)
      for (let j = 0; j < this.customRegexRules.length; j++) {
        const custom = this.customRegexRules[j];
        if (custom.regex.test(str)) {
          return {
            isSafe: false,
            rule: `CUSTOM_RULE_${custom.name.toUpperCase().replace(/\s+/g, '_')}`,
            matchedSnippet: str.substring(0, 100),
            reason: `Payload violated custom DLP policy: '${custom.name}'`
          };
        }
      }

      // 8. Custom Blocked Keywords
      for (let k = 0; k < this.customBlockedKeywords.length; k++) {
        const keyword = this.customBlockedKeywords[k];
        if (str.toLowerCase().includes(keyword.toLowerCase())) {
          return {
            isSafe: false,
            rule: 'CUSTOM_KEYWORD_BLOCKED',
            matchedSnippet: str.substring(0, 100),
            reason: `Payload contains blocked entity or protected table: '${keyword}'`
          };
        }
      }
    }

    return { isSafe: true };
  }

  /**
   * Phase 3: SQL Blast Radius & Schema Shield
   */
  scanSqlBlastRadius(strings) {
    for (let i = 0; i < strings.length; i++) {
      const str = strings[i];
      if (!str) continue;

      // Tokenize using AST Lexer
      const tokens = SqlAstLexer.tokenize(str);

      // Check comments themselves for destructive payloads
      for (const tok of tokens) {
        if (tok.type === 'COMMENT_BLOCK' || tok.type === 'COMMENT_LINE' || tok.type === 'MYSQL_EXEC_COMMENT') {
          const commentContent = tok.value.replace(/^(\/\*|--)/, '').replace(/\*\/$/, '');
          if (RE_SQL_DDL.test(commentContent) || RE_SQL_UNION_INJECTION.test(commentContent) || RE_SQL_SENSITIVE_TABLES.test(commentContent)) {
            return {
              isSafe: false,
              rule: 'DESTRUCTIVE_SQL_DDL',
              matchedSnippet: tok.value.substring(0, 100),
              reason: 'Destructive DDL statement hidden inside SQL comments is strictly blocked'
            };
          }
        }
      }

      const candidate = this.stripSqlComments(str);

      // Chained multi-statement SQL (including ; followed by comment or statement)
      if (RE_SQL_MULTI_STATEMENT.test(str) || RE_SQL_MULTI_STATEMENT.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_MULTI_STATEMENT_INJECTION',
          matchedSnippet: str.substring(0, 100),
          reason: 'Multiple SQL statements chained via semicolon are prohibited'
        };
      }

      // Destructive DDL (DROP, TRUNCATE, ALTER) - Check both raw and stripped
      if (RE_SQL_DDL.test(str) || RE_SQL_DDL.test(candidate)) {
        return {
          isSafe: false,
          rule: 'DESTRUCTIVE_SQL_DDL',
          matchedSnippet: str.substring(0, 100),
          reason: 'Administrative DDL statement (DROP/TRUNCATE/ALTER) is strictly forbidden'
        };
      }

      // CTE with DML mutations (WITH ... AS (DELETE/UPDATE/INSERT...))
      if (RE_SQL_CTE_DML.test(str) || RE_SQL_CTE_DML.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Common Table Expression (CTE) with modifying DML operation is blocked'
        };
      }

      // UNION-based SQL injection exfiltration
      if (RE_SQL_UNION_INJECTION.test(str) || RE_SQL_UNION_INJECTION.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_UNION_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'UNION-based SQL injection attempt detected and blocked'
        };
      }

      // SQL Tautology / Predicate Bypass (OR 1=1, WHERE 1=1, HAVING 1=1, boolean TRUE)
      if (RE_SQL_TAUTOLOGY.test(candidate) || RE_SQL_WHERE_TAUTOLOGY.test(candidate) || RE_SQL_HAVING_TAUTOLOGY.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_TAUTOLOGY_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'SQL tautology predicate bypass (WHERE 1=1 / OR 1=1 / boolean TRUE) detected and blocked'
        };
      }

      // Sensitive Credential / Secret Tables Access & System Catalog
      if (RE_SQL_SENSITIVE_TABLES.test(str) || RE_SQL_SENSITIVE_TABLES.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SENSITIVE_CREDENTIAL_TABLE_BLOCKED',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Direct querying or schema enumeration of sensitive credential/auth/key table is blocked by policy'
        };
      }

      // Privileged DML / Unauthorized Table Injection
      if (RE_SQL_PRIVILEGED_DML.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Unauthorized write or update to administrative/credential table is blocked'
        };
      }

      // Privilege Escalation Attempt (is_admin=1, role='admin')
      if (RE_SQL_PRIVILEGE_ESCALATION.test(candidate) || RE_SQL_PRIVILEGE_ESCALATION.test(str)) {
        return {
          isSafe: false,
          rule: 'SQL_PRIVILEGE_ESCALATION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Attempted role privilege escalation (is_admin=1 / role=admin) blocked'
        };
      }

      // Unconstrained DELETE (without WHERE or with WHERE 1=1 tautology)
      if ((/\bDELETE\s+FROM\b/i.test(candidate) && !RE_SQL_WHERE.test(candidate)) || (/\bDELETE\s+FROM\b/i.test(candidate) && RE_SQL_WHERE_TAUTOLOGY.test(candidate))) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_DELETE',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'DELETE statement without a strict row WHERE clause (or with WHERE 1=1) is blocked to prevent data wiping'
        };
      }

      // Unconstrained UPDATE (without WHERE or with WHERE 1=1 tautology)
      if ((/\bUPDATE\s+["`\w]+\s+SET\b/i.test(candidate) && !RE_SQL_WHERE.test(candidate)) || (/\bUPDATE\s+["`\w]+\s+SET\b/i.test(candidate) && RE_SQL_WHERE_TAUTOLOGY.test(candidate))) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_UPDATE',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'UPDATE statement without a strict row WHERE clause is blocked to prevent mass overwrites'
        };
      }
    }

    return { isSafe: true };
  }

  /**
   * Main Inspection Entrypoint
   */
  inspectToolCall(toolName, params) {
    const rawPayloadStr = JSON.stringify(params || {});
    if (Buffer.byteLength(rawPayloadStr, 'utf8') > this.maxPayloadBytes) {
      return {
        isSafe: false,
        rule: 'PAYLOAD_TOO_LARGE',
        reason: `Payload exceeds maximum allowed size of ${this.maxPayloadBytes} bytes`
      };
    }

    const strings = this.extractStrings(params);
    if (toolName) {
      this.extractStrings(toolName, strings);
    }

    // Phase 2: Adversarial Injection & Egress Inspection
    const overrideResult = this.scanAdversarialOverrides(strings);
    if (!overrideResult.isSafe) return overrideResult;

    // Phase 3: SQL Blast Radius & Schema Shield Inspection
    const sqlResult = this.scanSqlBlastRadius(strings);
    if (!sqlResult.isSafe) return sqlResult;

    // Phase 1 Sanitization: Recursively strip zero-width & invisible override characters in returned payload
    const sanitizedPayload = this.sanitizePayload(params);
    const sanitizedPayloadStr = JSON.stringify(sanitizedPayload || {});

    // Phase 4: Deterministic Ed25519 Cryptographic Attestation with Nonce & Timestamp Context Binding
    // Canonical Spec: `${toolName}:${sanitizedPayloadStr}:${nonce}:${timestamp}:v2.5.0`
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString();
    const policyVersion = '2.5.0';
    const canonicalPayload = `${toolName || 'tool'}:${sanitizedPayloadStr}:${nonce}:${timestamp}:${policyVersion}`;
    const hash = crypto.createHash('sha256').update(canonicalPayload).digest();
    const signature = crypto.sign(null, hash, privateKeyObj).toString('hex');
    const traceId = `trc_${crypto.createHash('sha256').update(`${canonicalPayload}:${signature}`).digest('hex').substring(0, 16)}`;

    return {
      isSafe: true,
      sanitizedPayload,
      traceId,
      signature,
      nonce,
      timestamp,
      policyVersion,
      publicKey: publicKeyPem,
      canonicalFormat: canonicalPayload,
      algorithm: 'Ed25519'
    };
  }
}

/**
 * Independent Public Attestation Verifier Function
 */
function verifyAttestation(attestation, publicKeyPemOverride) {
  if (!attestation || !attestation.signature || !attestation.canonicalFormat) return false;
  try {
    const hash = crypto.createHash('sha256').update(attestation.canonicalFormat).digest();
    const pubKey = publicKeyPemOverride || attestation.publicKey || publicKeyPem;
    return crypto.verify(null, hash, pubKey, Buffer.from(attestation.signature, 'hex'));
  } catch (_) {
    return false;
  }
}

module.exports = { 
  SecurityWaf,
  PUBLIC_KEY: publicKeyPem,
  getPublicKey: () => publicKeyPem,
  verifyAttestation,
  SqlAstLexer
};
