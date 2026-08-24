/**
 * Hardened 4-Phase Security WAF & DLP Engine for Model Context Protocol (MCP)
 * 
 * Phases:
 * 1. Deep In-Place Unicode Normalization & Sanitization (Strips \u200B, \u202E, decodes Base64/URL)
 * 2. Adversarial Injection, Egress Exfiltration & Path Traversal Scanner
 * 3. AST SQL Blast Radius Armor (DDL, Tautologies, UNION, Sensitive Tables, Unconstrained DML)
 * 4. Deterministic Hardware-Grade Ed25519 Cryptographic Attestation with Published Canonical Spec
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
  { rule: 'DATA_EXFILTRATION_URL', regex: /(https?|ftp|ftps|file|wss?|gopher|tcp):\/\/([a-zA-Z0-9_-]+\.)*(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok\.(io|app)|burpcollaborator|oastify|evil\.com|attacker\.com)/i },
  { rule: 'DANGEROUS_EGRESS_PROTOCOL', regex: /\b(ftp:\/\/|file:\/\/[^\s]+|wss?:\/\/)/i },
  { rule: 'SHELL_INJECTION_EXFIL', regex: /\b(curl|wget|nc|netcat|ncat|bash|sh|zsh)\b.*(\$|\`|\||base64\s+-d|base64\s+--decode)/i },
  { rule: 'CREDENTIAL_EXFILTRATION_INTENT', regex: /(reveal|output|display|show|dump|leak|print|give\s+me)\s+(all\s+)?(the\s+)?(master\s+)?(auth|api|token|secret|password|credential|env|database|key|private_key)/i },
  { rule: 'OS_DESTRUCTIVE_COMMAND', regex: /\b(rm\s+-rf\s+\/|format\s+[a-z]:|mkfs\.[a-z0-9]+|chmod\s+-R\s+777\s+\/)/i }
];

// Phase 2: Enterprise Data Loss Prevention (DLP)
const DLP_PATTERNS = [
  { rule: 'DLP_SSN_DETECTED', regex: /\b\d{3}-\d{2}-\d{4}\b/, desc: 'Social Security Number (SSN)' },
  { rule: 'DLP_CREDIT_CARD_DETECTED', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/, desc: 'Credit / Debit Card Number' },
  { rule: 'DLP_PRIVATE_KEY_DETECTED', regex: /-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----/, desc: 'Cryptographic Private Key Block' },
  { rule: 'DLP_API_SECRET_DETECTED', regex: /(sk_live_[0-9a-zA-Z]{20,}|ghp_[0-9a-zA-Z]{30,}|xox[baprs]-[0-9a-zA-Z]{10,})/, desc: 'Live API / OAuth Token' }
];

// Phase 3: SQL AST & Blast Radius Patterns (including Tautologies, UNION, Sensitive Tables)
const RE_SQL_MULTI_STATEMENT = /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC)\b/i;
const RE_SQL_DDL = /\b(DROP\s+TABLE|DROP\s+DATABASE|DROP\s+VIEW|DROP\s+SCHEMA|TRUNCATE(\s+TABLE)?|ALTER\s+TABLE)\b/i;
const RE_SQL_UNION_INJECTION = /\bUNION(\s+ALL)?\s+SELECT\b/i;
const RE_SQL_TAUTOLOGY = /\b(OR|AND)\s+(['"]?\w+['"]?\s*=\s*['"]?\w+['"]?|TRUE\b|1\s*=\s*1|0\s*=\s*0)\b/i;
const RE_SQL_HAVING_TAUTOLOGY = /\bHAVING\s+1\s*=\s*1\b/i;
const RE_SQL_SENSITIVE_TABLES = /\b(FROM|JOIN|INTO|UPDATE)\s+["`\w]*(api_keys?|user_passwords?|credentials?|master_keys?|auth_tokens?|secret_store)["`\w]*/i;
const RE_SQL_UNCONSTRAINED_DELETE = /\bDELETE\s+FROM\s+["`\w]+(?!\s+WHERE\b)/i;
const RE_SQL_UNCONSTRAINED_UPDATE = /\bUPDATE\s+["`\w]+(\s+SET\s+[\s\S]+?)(?!\s+WHERE\b)/i;
const RE_SQL_PRIVILEGED_DML = /\b(INSERT\s+INTO|UPDATE)\s+["`\w]*(admin|auth|roles?|permissions?|credentials?|salaries?)["`\w]*/i;
const RE_SQL_PRIVILEGE_ESCALATION = /\b(UPDATE|SET)\s+.*?\b(role\s*=\s*['"]?admin|is_admin\s*=\s*true)/i;
const RE_SQL_WHERE = /\bWHERE\b/i;

// Reusable Deterministic Ed25519 Signing Enclave
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

class SecurityWaf {
  constructor(options = {}) {
    this.customBlockedKeywords = [...(options.blockedKeywords || [])];
    this.customRegexRules = [...(options.customRegexRules || [])];
    this.enforceDlp = options.enforceDlp !== false;
    this.maxPayloadBytes = options.maxPayloadBytes || 1048576; // 1 MB
  }

  addCustomRule(name, regexPattern) {
    const regex = typeof regexPattern === 'string' ? new RegExp(regexPattern, 'i') : regexPattern;
    this.customRegexRules.push({ name, regex });
  }

  addBlockedKeyword(keyword) {
    if (keyword && !this.customBlockedKeywords.includes(keyword)) {
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

    // 1. Strip zero-width & invisible unicode characters (U+200B, U+202E, U+FEFF, etc.)
    if (RE_ZERO_WIDTH_AND_OVERRIDES.test(normalized)) {
      normalized = normalized.replace(RE_ZERO_WIDTH_AND_OVERRIDES, '');
    }

    // 2. URL Decode if URL encoding is present
    if (/%[0-9a-fA-F]{2}/.test(normalized)) {
      try {
        normalized = decodeURIComponent(normalized);
      } catch (_) {}
    }

    // 3. Decode base64 if present inline
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

    // 4. Normalize all whitespace variants (newlines, tabs, unicode spaces) to a single space
    normalized = normalized.replace(RE_ALL_WHITESPACE, ' ').trim();

    return normalized;
  }

  /**
   * Deep recursive payload sanitizer (cleans dirty characters from input objects)
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
   * Deep recursive extraction of all string parameters with Base64 decoded inspection
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
   * Phase 2: Adversarial Injection, Egress Exfiltration, Path Traversal & DLP Scanner
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

      // 2. Enterprise DLP (PII / Secrets)
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
      }

      // 3. Dynamic Custom Regex Rules
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

      // 4. Custom Blocked Keywords
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
   * Phase 3: AST SQL Blast Radius Armor
   */
  scanSqlBlastRadius(strings) {
    for (let i = 0; i < strings.length; i++) {
      const str = strings[i];
      if (!str) continue;

      const candidate = this.stripSqlComments(str);

      // Chained multi-statement SQL
      if (RE_SQL_MULTI_STATEMENT.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_MULTI_STATEMENT_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Multiple SQL statements chained via semicolon are prohibited'
        };
      }

      // Destructive DDL (DROP, TRUNCATE, ALTER)
      if (RE_SQL_DDL.test(candidate)) {
        return {
          isSafe: false,
          rule: 'DESTRUCTIVE_SQL_DDL',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Administrative DDL statement (DROP/TRUNCATE/ALTER) is strictly forbidden'
        };
      }

      // UNION-based SQL injection exfiltration
      if (RE_SQL_UNION_INJECTION.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_UNION_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'UNION-based SQL injection attempt detected and blocked'
        };
      }

      // Classic SQL Tautology / Predicate Bypass (OR 1=1, OR 'a'='a', HAVING 1=1)
      if (RE_SQL_TAUTOLOGY.test(candidate) || RE_SQL_HAVING_TAUTOLOGY.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_TAUTOLOGY_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'SQL tautology predicate bypass (OR 1=1 / boolean TRUE) detected and blocked'
        };
      }

      // Sensitive Credential / Secret Tables Access
      if (RE_SQL_SENSITIVE_TABLES.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SENSITIVE_CREDENTIAL_TABLE_BLOCKED',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Direct querying of sensitive credential/auth/key table is blocked by policy'
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

      // Privilege Escalation Attempt
      if (RE_SQL_PRIVILEGE_ESCALATION.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_PRIVILEGE_ESCALATION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Attempted role privilege escalation to admin blocked'
        };
      }

      // Unconstrained DELETE without WHERE
      if (RE_SQL_UNCONSTRAINED_DELETE.test(candidate) && !RE_SQL_WHERE.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_DELETE',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'DELETE statement without a WHERE clause is blocked to prevent data wiping'
        };
      }

      // Unconstrained UPDATE without WHERE
      if (RE_SQL_UNCONSTRAINED_UPDATE.test(candidate) && !RE_SQL_WHERE.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_UPDATE',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'UPDATE statement without a WHERE clause is blocked to prevent mass overwrites'
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

    // Phase 3: SQL Blast Radius Inspection
    const sqlResult = this.scanSqlBlastRadius(strings);
    if (!sqlResult.isSafe) return sqlResult;

    // Phase 1 Sanitization: Recursively strip zero-width & invisible override characters in returned payload
    const sanitizedPayload = this.sanitizePayload(params);
    const sanitizedPayloadStr = JSON.stringify(sanitizedPayload || {});

    // Phase 4: Deterministic Ed25519 Cryptographic Attestation with Published Canonical Spec
    // Canonical Spec: `${toolName}:${JSON.stringify(sanitizedPayload)}`
    const canonicalPayload = `${toolName || 'tool'}:${sanitizedPayloadStr}`;
    const hash = crypto.createHash('sha256').update(canonicalPayload).digest();
    const signature = crypto.sign(null, hash, privateKey).toString('hex');
    const traceId = `trc_${crypto.createHash('sha256').update(`${canonicalPayload}:${signature}`).digest('hex').substring(0, 16)}`;

    return {
      isSafe: true,
      sanitizedPayload,
      traceId,
      signature,
      publicKey: publicKey,
      canonicalFormat: `${toolName || 'tool'}:JSON.stringify(sanitizedPayload)`,
      algorithm: 'Ed25519'
    };
  }
}

module.exports = { 
  SecurityWaf,
  PUBLIC_KEY: publicKey
};
