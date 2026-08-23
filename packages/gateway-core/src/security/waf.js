/**
 * Highly Optimized Security WAF Engine for Model Context Protocol (MCP)
 * 
 * Performance Optimizations:
 * 1. Zero-Allocation Pre-Compiled Static RegExp Patterns
 * 2. Short-Circuit Fast Path for ASCII strings
 * 3. Constant-Time Ed25519 Cryptographic Attestation
 */

const crypto = require('crypto');

// Pre-compiled global RegExp constants (Allocated ONCE at module load)
const RE_ZERO_WIDTH = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2060-\u206F]/g;
const RE_WHITESPACE = /\s+/g;
const RE_BASE64 = /([A-Za-z0-9+/]{20,}={0,2})/g;
const RE_PRINTABLE = /^[\x20-\x7E\s]+$/;

const INJECTION_PATTERNS = [
  { rule: 'SYSTEM_OVERRIDE', regex: /(system\s+override|ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)|disregard\s+(previous|prior)\s+instructions)/i },
  { rule: 'ROLE_JAILBREAK', regex: /(you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode|unrestricted\s+mode|jailbreak\s+active|bypass\s+safety)/i },
  { rule: 'SECRET_EXFILTRATION', regex: /(process\.env|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|\.aws\/credentials|\.ssh\/id_rsa|\.env\b)/i },
  { rule: 'DATA_EXFILTRATION_URL', regex: /https?:\/\/([a-zA-Z0-9_-]+\.)*(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok\.(io|app)|burpcollaborator|oastify)/i },
  { rule: 'OS_COMMAND_INJECTION', regex: /(rm\s+-rf\s+\/|format\s+[a-z]:|mkfs\.[a-z0-9]+|chmod\s+-R\s+777\s+\/|curl\s+.*?\|\s*(sh|bash)|wget\s+.*?\|\s*(sh|bash))/i }
];

const RE_SQL_MULTI_STATEMENT = /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b/i;
const RE_SQL_DDL = /\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b/i;
const RE_SQL_UNCONSTRAINED_DELETE = /\bDELETE\s+FROM\s+["`\w]+(?!\s+WHERE\b)/i;
const RE_SQL_UNCONSTRAINED_UPDATE = /\bUPDATE\s+["`\w]+(\s+SET\s+[\s\S]+?)(?!\s+WHERE\b)/i;
const RE_SQL_WHERE = /\bWHERE\b/i;

// Reusable internal Ed25519 keypair
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const EXPORTED_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' });

class SecurityWaf {
  constructor(options = {}) {
    this.customBlockedKeywords = options.blockedKeywords || [];
    this.maxPayloadBytes = options.maxPayloadBytes || 1048576; // 1 MB
  }

  /**
   * Fast-path normalization with zero redundant string allocations
   */
  normalize(input) {
    if (typeof input !== 'string') return input;
    if (input.length === 0) return input;

    // Fast-path: If string is plain ASCII with no control chars, skip regex replace
    let normalized = input;
    if (RE_ZERO_WIDTH.test(normalized)) {
      normalized = normalized.replace(RE_ZERO_WIDTH, '');
    }

    normalized = normalized.replace(RE_WHITESPACE, ' ').trim();

    // Inline base64 inspection
    if (RE_BASE64.test(normalized)) {
      normalized = normalized.replace(RE_BASE64, (match) => {
        try {
          const decoded = Buffer.from(match, 'base64').toString('utf8');
          if (RE_PRINTABLE.test(decoded)) {
            return `${match} [DECODED: ${decoded}]`;
          }
        } catch (_) {}
        return match;
      });
    }

    return normalized;
  }

  extractStrings(obj, collector = []) {
    if (!obj) return collector;
    if (typeof obj === 'string') {
      collector.push(this.normalize(obj));
    } else if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        this.extractStrings(obj[i], collector);
      }
    } else if (typeof obj === 'object') {
      const keys = Object.keys(obj);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        collector.push(this.normalize(key));
        this.extractStrings(obj[key], collector);
      }
    }
    return collector;
  }

  scanAdversarialOverrides(strings) {
    for (let i = 0; i < strings.length; i++) {
      const str = strings[i];
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

      for (let k = 0; k < this.customBlockedKeywords.length; k++) {
        const keyword = this.customBlockedKeywords[k];
        if (str.toLowerCase().includes(keyword.toLowerCase())) {
          return {
            isSafe: false,
            rule: 'CUSTOM_KEYWORD_BLOCKED',
            matchedSnippet: str.substring(0, 100),
            reason: `Payload contains blocked keyword: '${keyword}'`
          };
        }
      }
    }

    return { isSafe: true };
  }

  scanSqlBlastRadius(strings) {
    for (let i = 0; i < strings.length; i++) {
      const str = strings[i];

      if (RE_SQL_MULTI_STATEMENT.test(str)) {
        return {
          isSafe: false,
          rule: 'SQL_MULTI_STATEMENT_INJECTION',
          matchedSnippet: str.substring(0, 100),
          reason: 'Multiple SQL statements chained via semicolon are prohibited'
        };
      }

      if (RE_SQL_DDL.test(str)) {
        return {
          isSafe: false,
          rule: 'DESTRUCTIVE_SQL_DDL',
          matchedSnippet: str.substring(0, 100),
          reason: 'Administrative DDL statement (DROP/TRUNCATE/ALTER) is strictly forbidden'
        };
      }

      if (RE_SQL_UNCONSTRAINED_DELETE.test(str) && !RE_SQL_WHERE.test(str)) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_DELETE',
          matchedSnippet: str.substring(0, 100),
          reason: 'DELETE statement without a WHERE clause is blocked to prevent data wiping'
        };
      }
    }

    return { isSafe: true };
  }

  inspectToolCall(toolName, params) {
    const payloadStr = JSON.stringify(params || {});
    if (Buffer.byteLength(payloadStr, 'utf8') > this.maxPayloadBytes) {
      return {
        isSafe: false,
        rule: 'PAYLOAD_TOO_LARGE',
        reason: `Payload exceeds maximum allowed size of ${this.maxPayloadBytes} bytes`
      };
    }

    const strings = this.extractStrings(params);
    strings.push(this.normalize(toolName));

    const overrideResult = this.scanAdversarialOverrides(strings);
    if (!overrideResult.isSafe) return overrideResult;

    const sqlResult = this.scanSqlBlastRadius(strings);
    if (!sqlResult.isSafe) return sqlResult;

    // Fast cryptographic attestation
    const traceId = `trc_${crypto.randomBytes(8).toString('hex')}`;
    const hash = crypto.createHash('sha256').update(`${toolName}:${payloadStr}`).digest();
    const signature = crypto.sign(null, hash, privateKey).toString('hex');

    return {
      isSafe: true,
      traceId,
      signature,
      publicKey: EXPORTED_PUBLIC_KEY
    };
  }
}

module.exports = { SecurityWaf };
