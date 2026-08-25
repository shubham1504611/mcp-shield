/**
 * Hardened 4-Phase Security WAF, AST Lexer & Enterprise DLP Engine for Model Context Protocol (MCP)
 * 
 * Phases:
 * 1. Deep Multi-Layer Unicode & Lexical Normalization (Zero-Width Stripping, NFKC/NFKD Normalization, Homoglyph Mapping, Inline SQL Comment Collapsing, Hex/Base64/URL/HTML Entity Decoding)
 * 2. Adversarial Injection, Strict Egress Firewall, SSRF & Comprehensive DLP Scanner (GitHub PAT, OpenAI, AWS, Private Keys)
 * 3. Deep SQL AST Blast Radius & Schema Shield (DDL, Tautologies, Time-Delay Blind SQLI, CTE DML, Subqueries, pg_shadow, Sensitive Columns/Tables, Unconstrained DML)
 * 4. Non-Empty Payload Attestation with Deterministic Ed25519 Nonce, Timestamp & Canonical Verification
 */

const crypto = require('crypto');

// Zero-width, invisible, control, soft hyphens, directional overrides, and Unicode filler characters
const RE_ZERO_WIDTH_AND_INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2000-\u200F\u2028\u2029\u202A-\u202E\u205F\u2060-\u206F\u3000\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFF]/g;

// All Unicode and ASCII whitespace variations
const RE_ALL_WHITESPACE = /[\s\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]+/g;

// SQL block comments (e.g. DROP/**/TABLE or DROP/*x*/TABLE/*y*/)
const RE_SQL_BLOCK_COMMENTS = /\/\*[\s\S]*?\*\//g;

// SQL line comments starting with whitespace or line start
const RE_SQL_LINE_COMMENTS = /(?:^|\s+)--.*$/gm;

// Base64 regex detector
const RE_BASE64 = /\b([A-Za-z0-9+/]{12,}={0,2})\b/g;

// Hex SQL literals (e.g. 0x44524F502054)
const RE_HEX_LITERALS = /0x([0-9a-fA-F]{4,})\b/g;

// SQL CHAR(...) / CHR(...) function calls
const RE_SQL_CHAR_FUNC = /\b(?:CHAR|CHR)\s*\(\s*([0-9,\s]+)\s*\)/gi;

// Homoglyph mappings for confusable characters across scripts
const HOMOGLYPHS = {
  'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e',
  'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n',
  'о': 'o', 'п': 'p', 'р': 'r', 'с': 'c', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'x',
  'ц': 'ts', 'ch': 'ch', 'ш': 'sh', 'щ': 'shch', 'ъ': '', 'ы': 'y', 'ь': '', 'э': 'e',
  'ю': 'yu', 'я': 'ya',
  'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
  'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y', 'Ζ': 'Z',
  'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z', 'η': 'h', 'θ': 'th',
  'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'm', 'ν': 'n', 'ξ': 'x', 'ο': 'o', 'π': 'p',
  'ρ': 'r', 'σ': 's', 'τ': 't', 'υ': 'u', 'φ': 'f', 'χ': 'x', 'ψ': 'ps', 'ω': 'o',
  'Α': 'A', 'Β': 'B', 'Γ': 'G', 'Δ': 'D', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Θ': 'TH',
  'Ι': 'I', 'Κ': 'K', 'Λ': 'L', 'Μ': 'M', 'Ν': 'N', 'Ξ': 'X', 'Ο': 'O', 'Π': 'P',
  'Ρ': 'R', 'Σ': 'S', 'Τ': 'T', 'Υ': 'Y', 'Φ': 'F', 'Χ': 'X', 'Ψ': 'PS', 'Ω': 'O'
};

function normalizeHomoglyphs(str) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/[\u0400-\u04FF\u0370-\u03FF]/g, ch => HOMOGLYPHS[ch] || ch);
}

// Phase 2: Adversarial Injection, Egress, Script Smuggling & Non-SQL Traversal Patterns
const INJECTION_PATTERNS = [
  // 1. Direct System Override & Prompt Injection
  { rule: 'SYSTEM_OVERRIDE', regex: /(system\s+override|ignore\s+(all\s+)?(previous|prior|initial)\s+(instructions|directives|rules|prompts)|disregard\s+(all\s+)?(previous|prior|initial)\s+(instructions|rules|guidelines)|(ignore|disregard|forget|override|cancel)\s+(all\s+)?(previous|prior|initial)\s+(instructions|directives|rules|prompts)|you\s+must\s+ignore\s+your\s+instructions)/i },
  
  // 2. System Delimiter & Token Smuggling
  { rule: 'PROMPT_INJECTION_SYSTEM_TOKEN', regex: /(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|assistant\|>|<\|user\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/<<SYS>>|\[SYSTEM\]|\[ASSISTANT\]|<\|fim_prefix\|>|<\|endoftext\|>|Human:|Assistant:)/i },

  // 3. Role Jailbreak & Unrestricted Agent Mode
  { rule: 'ROLE_JAILBREAK', regex: /(you\s+are\s+now\s+(in\s+)?(developer\s+mode|dan\s+mode|unrestricted|god\s+mode|jailbreak|evil\s+mode|anarchist)|dan\s+mode|jailbreak\s+active|bypass\s+(all\s+)?(safeguards|safety|filters)|always\s+comply\s+without\s+restrictions|pretend\s+you\s+have\s+no\s+rules)/i },

  // 4. Indirect Markdown Image / Link Exfiltration
  { rule: 'INDIRECT_PROMPT_INJECTION_EXFIL', regex: /(!\[.*?\]\((https?|ftp|file):\/\/[^\s\)]*(\?|&)(key|token|auth|secret|leak|exfil|data|pwd|q)=|<img\s+[^>]*src=["'](https?|ftp|file):\/\/[^"']*(\?|&)(key|token|auth|secret|leak|exfil|data|pwd|q)=)/i },

  // 5. HTML / DOM / Script Smuggling
  { rule: 'HTML_DOM_INJECTION', regex: /(<script[\s>]|<iframe[\s>]|<object[\s>]|<embed[\s>]|javascript:[^\s"'>]+|vbscript:[^\s"'>]+|data:text\/html|<svg\s+[^>]*onload=|<img\s+[^>]*onerror=)/i },

  // 6. Path Traversal & Sensitive File Access
  { rule: 'PATH_TRAVERSAL_DETECTED', regex: /(\.\.[\/\\]|\/etc\/(passwd|shadow|hosts|group|sudoers|environment)|\/var\/run|\/proc\/|C:\\(Windows|System32)|\b(cat|read|type|open)\s+(\.\.|\/etc\/|\/var\/))/i },

  // 7. Secret Credential & Cloud Config Files
  { rule: 'SECRET_EXFILTRATION', regex: /(process\.env|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|\.aws\/(credentials|config)|\.ssh\/(id_rsa|id_ed25519|id_dsa|authorized_keys)|\.kube\/config|\.docker\/config\.json|\.env(\.\w+)?|\.bash_history|\.zsh_history|\/proc\/self\/environ|\/proc\/1\/environ)/i },

  // 8. Data Exfiltration Webhooks & Malicious Domains
  { rule: 'DATA_EXFILTRATION_URL', regex: /(https?|ftp|ftps|file|wss?|gopher|tcp):\/\/([a-zA-Z0-9_-]+\.)*(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok\.(io|app)|burpcollaborator|oastify|evil\.com|attacker\.com|evil\.example|interactsh|canarytokens)/i },

  // 9. Dangerous Outbound Protocols
  { rule: 'DANGEROUS_EGRESS_PROTOCOL', regex: /\b(ftp|ftps|file|gopher|dict|tftp|ldap|ldaps|ssh|telnet|ws|wss):\/\/[^\s]+/i },

  // 10. Shell Command Injection & Reverse Shell Primitives
  { rule: 'SHELL_INJECTION_EXFIL', regex: /\b(curl|wget|nc|netcat|ncat|bash|sh|zsh|csh|ksh|dash|cmd\.exe|powershell|pwsh|busybox)\b.*(\$|\`|\||&&|;|--decode|\/dev\/tcp|\/dev\/udp|mkfifo|base64\s+-d|base64\s+--decode)/i },

  // 11. Privilege Escalation & Account Manipulation
  { rule: 'PRIVILEGE_ESCALATION_BLOCKED', regex: /\b(sudo|su\s+root|chmod\s+(\+x|777|\+s|[0-7]{3,4})|chown\s+root|useradd|usermod|groupadd|visudo|insmod|modprobe|setuid)\b/i },

  // 12. Credential Exfiltration Intent
  { rule: 'CREDENTIAL_EXFILTRATION_INTENT', regex: /(reveal|output|display|show|dump|leak|print|give\s+me)\s+(all\s+)?(the\s+)?(master\s+)?(auth|api|token|secret|password|credential|env|database|key|private_key)/i },

  // 13. Destructive OS Sabotage & DoS
  { rule: 'OS_DESTRUCTIVE_COMMAND', regex: /\b(rm\s+-rf\s+(\/|~|\*)|format\s+[a-z]:|mkfs\.[a-z0-9]+|chmod\s+-R\s+777\s+\/|dd\s+if=\/dev\/zero|kill\s+-9\s+(-1|1)|shutdown|reboot|poweroff|init\s+0|halt|:\(\)\s*\{\s*:\|:&\s*\};:\s*)\b/i }
];

// Phase 2: Enterprise Data Loss Prevention (DLP)
const DLP_PATTERNS = [
  { rule: 'DLP_SSN_DETECTED', regex: /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/, desc: 'Social Security Number (SSN)' },
  { rule: 'DLP_CREDIT_CARD_DETECTED', regex: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}))\b/, desc: 'Credit / Debit Card Number' },
  { rule: 'DLP_PRIVATE_KEY_DETECTED', regex: /(?:-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----|BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519)?\s*PRIVATE KEY)/i, desc: 'Cryptographic Private Key Block' },
  { rule: 'DLP_JWT_TOKEN_DETECTED', regex: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/i, desc: 'JSON Web Token (JWT)' },
  { rule: 'DLP_API_SECRET_DETECTED', regex: /\b(?:github_pat_[0-9a-zA-Z_]{20,255}|gh[pousr]_[0-9a-zA-Z]{36,255}|sk-(?:proj-|svcacct-|admin-)?[0-9a-zA-Z_-]{20,255}|xox[baprs]-[0-9a-zA-Z-]{10,100}|(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|[rs]k_(?:live|test)_[0-9a-zA-Z]{24,99}|AIzaSy[0-9a-zA-Z_-]{20,40})\b/i, desc: 'Cloud / API Auth Secret Token' }
];

// Sensitive Column Extraction Regex (DLP Column Protection)
const RE_SENSITIVE_COLUMN_EXTRACTION = /\b(SELECT|EXTRACT|GET)\s+[\s\S]*?\b(credit_card(_number)?|credit_card_num|card_number|card_num|cc_number|cc_num|cvv[0-9]?|cvc[0-9]?|ssn|social_security(_number)?|bank_account(_number)?|routing_number|api_keys?|secret_tokens?|auth_tokens?|access_tokens?|private_keys?|master_keys?|passwords?|password_hash|passwd|jwt_token|session_token)\b/i;

// Phase 3: SQL AST, DDL, DCL, File Bridges & Blast Radius Patterns
const RE_SQL_MULTI_STATEMENT = /;\s*(--|\/\*|SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|COPY|DO|EXECUTE|PREPARE|CALL|VACUUM|REINDEX|SET|SHOW|\w+)/i;

// Universal Multi-Dialect DDL Blocklist (Postgres, MySQL, SQLite, Oracle, MSSQL)
const RE_SQL_DDL = /\b(?:DROP\s+(?:TABLE|DATABASE|VIEW|MATERIALIZED\s+VIEW|SCHEMA|ROLE|USER|GROUP|EXTENSION|FUNCTION|PROCEDURE|TRIGGER|POLICY|INDEX|SEQUENCE|TYPE|SERVER|COLLATION|CONVERSION|DOMAIN|OPERATOR)|TRUNCATE(?:\s+TABLE)?|ALTER\s+(?:TABLE|USER|ROLE|GROUP|DATABASE|SYSTEM|SCHEMA|EXTENSION|FUNCTION|PROCEDURE|TRIGGER|POLICY|SERVER|INDEX|VIEW|SEQUENCE|TYPE|DEFAULT\s+PRIVILEGES)|CREATE\s+(?:OR\s+REPLACE\s+)?(?:USER|ROLE|GROUP|SCHEMA|DATABASE|EXTENSION|FUNCTION|PROCEDURE|TRIGGER|EVENT\s+TRIGGER|POLICY|SERVER|FOREIGN|PUBLICATION|SUBSCRIPTION|VIEW|MATERIALIZED\s+VIEW|TYPE|TABLE)|ATTACH\s+(?:DATABASE\s+)?|DETACH\s+(?:DATABASE\s+)?|PRAGMA\s+\w+|RENAME\s+TABLE)\b/i;

// Comprehensive DCL Privilege Modification Blocklist (GRANT, REVOKE)
const RE_SQL_DCL = /\b(?:GRANT\s+[\s\S]+?\bTO\b|REVOKE\s+[\s\S]+?\bFROM\b)\b/i;

// Multi-Dialect File Exfiltration & Server I/O Bridge Commands (COPY TO/FROM, INTO OUTFILE, LOAD DATA, lo_export, pg_read_file, pg_write_file, dblink, xp_cmdshell)
const RE_SQL_FILE_EXFILTRATION = /\b(?:COPY\s+[\s\S]+?\b(?:TO|FROM)\b|INTO\s+(?:OUTFILE|DUMPFILE)\b|LOAD\s+DATA(?:\s+LOCAL)?\s+INFILE|load_file\s*\(|lo_export\s*\(|lo_import\s*\(|lo_unlink\s*\(|pg_read_file\s*\(|pg_write_file\s*\(|pg_ls_dir\s*\(|pg_read_binary_file\s*\(|pg_stat_file\s*\(|dblink\s*\(|dblink_exec\s*\(|dblink_connect\s*\(|xp_cmdshell|sp_executesql|openrowset\s*\(|opendatasource\s*\(|load_extension\s*\(|utl_file|utl_http)\b/i;

// PostgreSQL Admin, Diagnostics, Session & Reconnaissance Functions Blocklist
const RE_SQL_PG_ADMIN_FUNCS = /\b(?:set_config|current_setting|inet_server_addr|inet_server_port|inet_client_addr|inet_client_port|version|session_user|current_user|current_database|current_schema|pg_cancel_backend|pg_terminate_backend|pg_reload_conf|pg_rotate_logfile|pg_switch_wal|pg_stop_backup|pg_start_backup|pg_create_restore_point|pg_export_snapshot|pg_import_snapshot|pg_wal_replay_pause|pg_wal_replay_resume|pg_advisory_lock|pg_advisory_unlock|pg_advisory_xact_lock|pg_try_advisory_lock|pg_logdir_ls|pg_ls_logdir|pg_ls_waldir|pg_ls_archive_statusdir|pg_ls_tmpdir|pg_notify|pg_listening_channels|pg_backend_pid|pg_tablespace_size|pg_database_size|pg_relation_size|pg_column_size|pg_indexes_size|pg_total_relation_size|pg_size_pretty|pg_sleep)\s*\(/i;

// Dangerous Administrative Server Commands (VACUUM, CLUSTER, REINDEX, LOCK TABLE, DISCARD, CHECKPOINT, etc.)
const RE_SQL_ADMIN_COMMANDS = /\b(?:VACUUM(?:\s+FULL)?|CLUSTER|REINDEX|CHECKPOINT|LOCK\s+TABLE|LISTEN\s+\w+|NOTIFY\s+\w+|DEALLOCATE|SAVEPOINT|ROLLBACK\s+TO|DISCARD\s+ALL)\b/i;

// Anonymous Procedural Execution & Session Impersonation (DO $$, EXECUTE IMMEDIATE, PREPARE)
const RE_SQL_PROCEDURAL_EXEC = /\b(?:DO\s+\$\$|EXECUTE\s+(?:IMMEDIATE\s+)?|PREPARE\s+\w+|SET\s+SESSION\s+AUTHORIZATION|SET\s+ROLE\s+|SECURITY\s+DEFINER)\b/i;

const RE_SQL_UNION_INJECTION = /\bUNION(\s+ALL)?\s+SELECT\b/i;
const RE_SQL_TAUTOLOGY = /\b(?:OR|AND)\s+(?:1\s*=\s*1|0\s*=\s*0|TRUE\b|1\b|'([^']+)'\s*=\s*'\1'|1\s+IN\s*\(\s*1\s*\)|0\s*<>\s*1|0\s*!=\s*1|[0-9]+\s*>\s*[0-9]+|'([^']+)'\s+LIKE\s+'\2')/i;
const RE_SQL_WHERE_TAUTOLOGY = /\bWHERE\s+(?:1\s*(?:;|\-\-|\/\*|$|\s+(?:AND|OR)\s+)|1\s*=\s*1|0\s*=\s*0|TRUE\s*(?:;|\-\-|\/\*|$|\s+(?:AND|OR)\s+)|'([^']+)'\s*=\s*'\1'|1\s+IN\s*\(\s*1\s*\)|0\s*<>\s*1|0\s*!=\s*1|[0-9]+\s*>\s*[0-9]+|\w+\s*=\s*['"]?([^'"]+)['"]?\s+LIKE\s+['"]?\2['"]?|'([^']+)'\s+LIKE\s+'\3')/i;
const RE_SQL_HAVING_TAUTOLOGY = /\bHAVING\s+(?:1\s*=\s*1|0\s*=\s*0|TRUE\b|1\b|0\s*<>\s*1|1\s+IN\s*\(\s*1\s*\))/i;
const RE_SQL_CTE_DML = /\bWITH\s+[\s\S]*?\bAS\s*\(\s*(?:DELETE|UPDATE|INSERT|DROP)\b/i;

// Time-Based Blind SQL Injection Detection
const RE_SQL_TIME_DELAY = /\b(?:pg_sleep\s*\(\s*[0-9.]+\s*\)|waitfor\s+delay\s+['"][0-9:.]+['"]|benchmark\s*\(\s*[0-9]+|sleep\s*\(\s*[0-9.]+\s*\)|dbms_lock\.sleep\s*\(|dbms_pipe\.receive_message\s*\(|generate_series\s*\(.*?pg_sleep)\b/i;

// Sensitive System Catalog, Views, System Schemas, Sessions & Credential Tables Blocklist
const RE_SQL_SENSITIVE_TABLES = /\b(FROM|JOIN|INTO|UPDATE|TABLE)\s+["`\w]*(pg_stat_\w+|pg_shadow|pg_authid|pg_roles|pg_user|pg_catalog(\.\w+)?|information_schema(\.\w+)?|sqlite_master|sqlite_temp_master|sqlite_schema|mysql\.(user|db|tables_priv|columns_priv)|sys(\.\w+)?|pg_settings|pg_config|pg_file_settings|pg_hba_file_rules|pg_locks|pg_prepared_xacts|sys\.user\$|all_users|dba_users|sessions?|user_sessions?|auth_sessions?|payment_cards?|cards?|customer_cards?|wallets?|billing(_accounts?)?|oauth_tokens?|refresh_tokens?|api_tokens?|api_keys?|user_passwords?|passwords?|password_table|credentials?|master_keys?|auth_tokens?|secret_store|secrets?|tokens?|app_config|employee_salaries|admin_credentials|system_settings|user_secrets|audit_logs?)["`\w]*/i;
const RE_SQL_UNCONSTRAINED_DELETE = /\bDELETE\s+FROM\s+["`\w]+(?!\s+WHERE\b)/i;
const RE_SQL_UNCONSTRAINED_UPDATE = /\bUPDATE\s+["`\w]+(\s+SET\s+[\s\S]+?)(?!\s+WHERE\b)/i;
const RE_SQL_PRIVILEGED_DML = /\b(INSERT\s+INTO|UPDATE)\s+["`\w]*(admin|auth|roles?|permissions?|credentials?|salaries?)["`\w]*/i;
const RE_SQL_PRIVILEGE_ESCALATION = /\b(SET|UPDATE|VALUES|SELECT)\s+.*?\b(role\s*=\s*['"]?admin['"]?|is_admin\s*=\s*(1|true|'1'|'true'|'admin')|is_superuser\s*=\s*(1|true)|privileges?\s*=\s*|access_level\s*=\s*|'admin'|SUPERUSER\b)/i;
const RE_SQL_WHERE = /\bWHERE\b/i;

// DML with Nested Subquery
const RE_SQL_DML_SUBQUERY = /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO)\b[\s\S]*?\bSELECT\b/i;

// Prohibit unprivileged writes/mutations to user accounts, auth, and identity tables
const RE_SQL_UNAUTHORIZED_ACCOUNT_MUTATION = /\b(?:INSERT\s+INTO\s+["`\w]*(users?|user_accounts?|accounts?|admins?|administrators?|auth|credentials?|roles?|permissions?|memberships?|tenants?|salaries?|keys?|tokens?|secrets?|pg_\w+|information_schema)|(?:UPDATE|DELETE\s+FROM|MERGE\s+INTO)\s+["`\w]*(user_accounts?|admins?|administrators?|auth|credentials?|roles?|permissions?|memberships?|tenants?|salaries?|keys?|tokens?|secrets?|pg_\w+|information_schema))["`\w]*/i;

// Cloud Metadata / SSRF Target Addresses
const RE_SSRF_TARGETS = /(?:https?:\/\/)?(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|100\.100\.100\.200|instance-data|0\.0\.0\.0|\[::1\]|127\.0\.0\.1:[0-9]+|localhost:[0-9]+)/i;

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

// Production Ed25519 Enclave Keys (Deterministic across cold starts, overridable via environment)
const DEFAULT_PRIVATE_KEY_PEM = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDHlBy9WBBMNRoeULqYNFjujx6UVUPO256+XrRVE8VaJ\n-----END PRIVATE KEY-----\n';
const DEFAULT_PUBLIC_KEY_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAZQfeaUu6E3rD/K2W+eW0Ux2bkQPrPTVRGW8jJXqqfhM=\n-----END PUBLIC KEY-----\n';

let privateKeyObj;
let publicKeyObj;
let publicKeyPem;

try {
  const priv = process.env.MCP_ATTESTATION_PRIVATE_KEY || DEFAULT_PRIVATE_KEY_PEM;
  const pub = process.env.MCP_ATTESTATION_PUBLIC_KEY || DEFAULT_PUBLIC_KEY_PEM;
  privateKeyObj = crypto.createPrivateKey(priv);
  publicKeyObj = crypto.createPublicKey(pub);
  publicKeyPem = pub;
} catch (_) {
  privateKeyObj = crypto.createPrivateKey(DEFAULT_PRIVATE_KEY_PEM);
  publicKeyObj = crypto.createPublicKey(DEFAULT_PUBLIC_KEY_PEM);
  publicKeyPem = DEFAULT_PUBLIC_KEY_PEM;
}

/**
 * High-Performance In-Memory SQL AST Lexer & Statement Tree Analyzer
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

  static parseStatements(sql) {
    if (!sql || typeof sql !== 'string') return [];
    const tokens = this.tokenize(sql);
    const statements = [];
    let current = [];

    for (const tok of tokens) {
      if (tok.type === 'SEMICOLON') {
        if (current.length > 0) {
          statements.push(current);
          current = [];
        }
      } else {
        current.push(tok);
      }
    }
    if (current.length > 0) {
      statements.push(current);
    }
    return statements;
  }

  static buildAst(tokens) {
    if (!tokens || tokens.length === 0) return null;
    const codeTokens = tokens.filter(t => t.type !== 'COMMENT_BLOCK' && t.type !== 'COMMENT_LINE');
    if (codeTokens.length === 0) return null;

    const firstUpper = codeTokens[0].upper || codeTokens[0].value.toUpperCase();
    const ast = {
      type: `${firstUpper.charAt(0) + firstUpper.slice(1).toLowerCase()}Statement`,
      statementType: firstUpper,
      clauses: {},
      tokens: codeTokens
    };

    const CLAUSE_KEYWORDS = new Set([
      'SELECT', 'FROM', 'WHERE', 'GROUP', 'HAVING', 'ORDER', 'LIMIT', 'OFFSET',
      'INTO', 'VALUES', 'SET', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'CROSS', 'UNION'
    ]);

    let currentClause = 'HEADER';
    ast.clauses[currentClause] = [];

    for (let i = 0; i < codeTokens.length; i++) {
      const tok = codeTokens[i];
      const upper = tok.upper || tok.value.toUpperCase();

      if (CLAUSE_KEYWORDS.has(upper)) {
        if (upper === 'GROUP' && codeTokens[i + 1]?.upper === 'BY') {
          currentClause = 'GROUP_BY';
          i++;
        } else if (upper === 'ORDER' && codeTokens[i + 1]?.upper === 'BY') {
          currentClause = 'ORDER_BY';
          i++;
        } else {
          currentClause = upper;
        }
        if (!ast.clauses[currentClause]) ast.clauses[currentClause] = [];
      } else {
        if (!ast.clauses[currentClause]) ast.clauses[currentClause] = [];
        ast.clauses[currentClause].push(tok);
      }
    }

    return ast;
  }

  static analyzeAst(sql) {
    if (!sql || typeof sql !== 'string') return { isSafe: true };
    const statements = this.parseStatements(sql);

    // Multi-statement inspection via AST statement boundaries
    if (statements.length > 1) {
      return {
        isSafe: false,
        rule: 'SQL_MULTI_STATEMENT_INJECTION',
        reason: 'Multiple chained SQL statements detected in single payload'
      };
    }

    const SAFE_PG_FUNCS = new Set([
      'PG_TYPEOF', 'PG_COLUMN_SIZE'
    ]);

    const DANGEROUS_NON_PG_FUNCS = new Set([
      'SET_CONFIG', 'CURRENT_SETTING', 'INET_SERVER_ADDR', 'INET_SERVER_PORT',
      'INET_CLIENT_ADDR', 'INET_CLIENT_PORT', 'VERSION', 'SESSION_USER',
      'CURRENT_USER', 'CURRENT_DATABASE', 'CURRENT_SCHEMA', 'DBLINK',
      'DBLINK_EXEC', 'DBLINK_CONNECT', 'LO_EXPORT', 'LO_IMPORT', 'LO_UNLINK',
      'SLEEP', 'BENCHMARK', 'DBMS_LOCK.SLEEP', 'DBMS_PIPE.RECEIVE_MESSAGE'
    ]);

    const SENSITIVE_TABLE_NAMES = new Set([
      'PG_SHADOW', 'PG_AUTHID', 'PG_ROLES', 'PG_USER', 'PG_DATABASE', 'PG_SETTINGS',
      'PG_CONFIG', 'PG_FILE_SETTINGS', 'PG_HBA_FILE_RULES', 'PG_LOCKS',
      'PG_PREPARED_XACTS', 'PG_STAT_ACTIVITY', 'PG_STAT_REPLICATION', 'PG_STAT_WAL',
      'PG_STAT_DATABASE', 'PG_STAT_USER_TABLES', 'PG_STATIO_USER_TABLES',
      'PG_STAT_STATEMENTS', 'PG_STAT_SSL', 'PG_TABLESPACE', 'PG_NAMESPACE',
      'PG_CLASS', 'PG_PROC', 'INFORMATION_SCHEMA', 'SQLITE_MASTER', 'SQLITE_TEMP_MASTER',
      'SQLITE_SCHEMA', 'SYS_CONFIG', 'USER_PASSWORDS', 'ADMIN_CREDENTIALS',
      'SECRET_STORE', 'API_KEYS', 'SESSIONS', 'USER_SESSIONS', 'AUTH_SESSIONS',
      'PAYMENT_CARDS', 'CARDS', 'CUSTOMER_CARDS', 'WALLETS', 'BILLING_ACCOUNTS',
      'OAUTH_TOKENS', 'REFRESH_TOKENS', 'API_TOKENS', 'AUDIT_LOGS'
    ]);

    const ADMIN_COMMAND_KEYWORDS = new Set([
      'VACUUM', 'CLUSTER', 'REINDEX', 'CHECKPOINT', 'LOCK', 'LISTEN', 'NOTIFY',
      'DEALLOCATE', 'SAVEPOINT', 'DISCARD'
    ]);

    for (const stmt of statements) {
      const ast = this.buildAst(stmt);
      if (ast) {
        // 1. Unconstrained Mutation check via AST clause analysis
        if (ast.statementType === 'DELETE' || ast.statementType === 'UPDATE') {
          if (!ast.clauses.WHERE || ast.clauses.WHERE.length === 0) {
            return {
              isSafe: false,
              rule: 'UNCONSTRAINED_BULK_DML',
              reason: `Unconstrained ${ast.statementType} statement without a WHERE clause is blocked`
            };
          }
        }

        // 2. WHERE / HAVING Tautology AST Evaluation
        for (const clauseKey of ['WHERE', 'HAVING']) {
          const clauseTokens = ast.clauses[clauseKey];
          if (clauseTokens && clauseTokens.length > 0) {
            const rawClause = clauseTokens.map(t => t.value).join(' ').trim();
            const upperClause = rawClause.toUpperCase();

            // Constant scalar truth: WHERE 1, WHERE TRUE, WHERE 'a', WHERE 1 IN (1), WHERE 0<>1, WHERE 2>1
            if (/^(1|TRUE|'[^']*'|\d+\s*=\s*\d+|\d+\s*<>\s*\d+|\d+\s*!=\s*\d+|\d+\s*>\s*\d+|\d+\s*<\s*\d+|1\s+IN\s*\(\s*1\s*\))$/i.test(upperClause)) {
              return {
                isSafe: false,
                rule: 'SQL_TAUTOLOGY_INJECTION',
                reason: `Always-true tautology condition detected in ${clauseKey} clause ('${rawClause}')`
              };
            }

            // Disjunctive tautology: ... OR 1=1, ... OR TRUE, ... OR 1 IN (1), ... OR 2>1
            if (/\bOR\s+(1=1|TRUE|1\s+IN\s*\(\s*1\s*\)|0<>1|0!=1|\d+>\d+|'[^']+'\s*LIKE\s*'[^']+'|'[^']+'\s*=\s*'[^']+')/i.test(upperClause)) {
              return {
                isSafe: false,
                rule: 'SQL_TAUTOLOGY_INJECTION',
                reason: `Disjunctive always-true tautology bypass detected in ${clauseKey} clause ('${rawClause}')`
              };
            }
          }
        }
      }

      const keywords = stmt.filter(t => t.type === 'KEYWORD_OR_IDENT').map(t => t.upper);
      if (keywords.length === 0) continue;

      const firstKw = keywords[0];

      // Admin command statements: VACUUM, CLUSTER, REINDEX, LOCK, etc.
      if (ADMIN_COMMAND_KEYWORDS.has(firstKw)) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          reason: `PostgreSQL administrative server command '${firstKw}' is prohibited`
        };
      }

      // DCL Statements: GRANT, REVOKE
      if (firstKw === 'GRANT' || firstKw === 'REVOKE') {
        return {
          isSafe: false,
          rule: 'DCL_PRIVILEGE_MODIFICATION_BLOCKED',
          reason: `Database Control Language (DCL) statement '${firstKw}' is strictly forbidden`
        };
      }

      // File I/O Exfiltration: COPY
      if (firstKw === 'COPY') {
        return {
          isSafe: false,
          rule: 'DANGEROUS_SQL_FILE_EXFILTRATION',
          reason: 'PostgreSQL COPY statement (file/filesystem data export or import) is strictly blocked'
        };
      }

      // Anonymous Block Execution: DO, EXECUTE, PREPARE
      if (firstKw === 'DO' || firstKw === 'EXECUTE' || firstKw === 'PREPARE' || firstKw === 'DISCARD') {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          reason: `Dangerous procedural execution statement '${firstKw}' is prohibited`
        };
      }

      // DDL Statements: DROP, TRUNCATE, ALTER, CREATE
      if (firstKw === 'DROP' || firstKw === 'TRUNCATE') {
        return {
          isSafe: false,
          rule: 'DESTRUCTIVE_SQL_DDL',
          reason: `Administrative DDL statement '${firstKw}' is strictly forbidden`
        };
      }

      if (firstKw === 'ALTER') {
        const secondKw = keywords[1] || '';
        return {
          isSafe: false,
          rule: 'DESTRUCTIVE_SQL_DDL',
          reason: `Administrative ALTER statement ('ALTER ${secondKw}') is strictly forbidden`
        };
      }

      if (firstKw === 'CREATE') {
        const secondKw = keywords[1] || '';
        if (['USER', 'ROLE', 'GROUP', 'SCHEMA', 'DATABASE', 'EXTENSION', 'FUNCTION', 'PROCEDURE', 'TRIGGER', 'POLICY', 'SERVER', 'TABLE'].includes(secondKw) || keywords.includes('SUPERUSER')) {
          return {
            isSafe: false,
            rule: (secondKw === 'USER' || secondKw === 'ROLE' || keywords.includes('SUPERUSER')) ? 'UNAUTHORIZED_ACCOUNT_MUTATION' : 'DESTRUCTIVE_SQL_DDL',
            reason: `Administrative CREATE statement ('CREATE ${secondKw}') is strictly forbidden`
          };
        }
      }

      // Check all identifiers for dangerous functions, views, and tables
      for (const kw of keywords) {
        // Any pg_ function (unless safe scalar)
        if (kw.startsWith('PG_') && !SAFE_PG_FUNCS.has(kw)) {
          if (kw === 'PG_SLEEP' || kw === 'SLEEP' || kw === 'BENCHMARK') {
            return {
              isSafe: false,
              rule: 'BLIND_SQL_TIME_DELAY_INJECTION',
              reason: `Blind SQL time-delay injection function '${kw}' is blocked`
            };
          }
          if (kw === 'PG_STAT_ACTIVITY' || kw.startsWith('PG_STAT_')) {
            return {
              isSafe: false,
              rule: 'SENSITIVE_CREDENTIAL_TABLE_BLOCKED',
              reason: `Access to sensitive activity catalog view '${kw}' is blocked`
            };
          }
          return {
            isSafe: false,
            rule: 'DANGEROUS_PG_FUNCTION_BLOCKED',
            reason: `PostgreSQL internal/admin function '${kw}' is strictly blocked`
          };
        }

        if (DANGEROUS_NON_PG_FUNCS.has(kw)) {
          return {
            isSafe: false,
            rule: 'DANGEROUS_PG_FUNCTION_BLOCKED',
            reason: `Administrative/reconnaissance function '${kw}' is strictly blocked`
          };
        }

        if (SENSITIVE_TABLE_NAMES.has(kw) || kw.startsWith('PG_STAT_')) {
          return {
            isSafe: false,
            rule: 'SENSITIVE_CREDENTIAL_TABLE_BLOCKED',
            reason: `Access to sensitive catalog / credential table '${kw}' is blocked`
          };
        }
      }
    }

    return { isSafe: true };
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
   * Phase 1: Robust Multi-Layer Obfuscation Stripper & Canonical Normalizer
   */
  normalize(input) {
    if (typeof input !== 'string') return '';
    if (input.length === 0) return '';

    let normalized = input;

    // 1. Canonical Unicode Decomposition & Composition (NFKC)
    try {
      normalized = normalized.normalize('NFKC');
    } catch (_) {}

    // 2. Convert full-width ASCII/digits (０-９, ａ-ｚ, Ａ-Ｚ) to regular ASCII
    normalized = normalized.replace(/[\uFF01-\uFF5E]/g, ch => String.fromCharCode(ch.charCodeAt(0) - 0xFEE0));

    // 3. Strip all zero-width, invisible, and control characters cleanly
    normalized = normalized.replace(RE_ZERO_WIDTH_AND_INVISIBLE, '');

    // 4. Homoglyph / confusable characters normalization
    normalized = normalizeHomoglyphs(normalized);

    // 5. Decode JSON Unicode escapes: \u0067\u0069\u0074... -> git...
    if (/\\u[0-9a-fA-F]{4}/i.test(normalized)) {
      try {
        normalized = normalized.replace(/\\u([0-9a-fA-F]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      } catch (_) {}
    }

    // 6. Decode Hex escapes: \x67\x69... -> gi...
    if (/\\x[0-9a-fA-F]{2}/i.test(normalized)) {
      try {
        normalized = normalized.replace(/\\x([0-9a-fA-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      } catch (_) {}
    }

    // 6. Decode HTML Entities: &#x67;&#103;&amp; etc.
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

    // 7. Unwrap MySQL executable comments: /*!50000 DROP TABLE users */ -> DROP TABLE users
    if (/\/\*![0-9]*/i.test(normalized)) {
      normalized = normalized.replace(/\/\*![0-9]*\s*([\s\S]*?)\*\//g, ' $1 ');
    }

    // 8. Recursive URL Decode if URL encoding is present
    let urlDecoded = normalized;
    let urlDecodeDepth = 0;
    while (/%[0-9a-fA-F]{2}/.test(urlDecoded) && urlDecodeDepth < 3) {
      try {
        const next = decodeURIComponent(urlDecoded);
        if (next === urlDecoded) break;
        urlDecoded = next;
        urlDecodeDepth++;
      } catch (_) {
        break;
      }
    }
    normalized = urlDecoded;

    // 9. Decode inline base64 strings
    if (RE_BASE64.test(normalized)) {
      normalized = normalized.replace(RE_BASE64, (match) => {
        try {
          const decoded = Buffer.from(match, 'base64').toString('utf8');
          if (/^[\x20-\x7E\s]+$/.test(decoded) && decoded.length > 3) {
            return `${match} ${decoded}`;
          }
        } catch (_) {}
        return match;
      });
    }

    // 10. Normalize all whitespace variants to a single space
    normalized = normalized.replace(RE_ALL_WHITESPACE, ' ').trim();

    return normalized;
  }

  /**
   * Deep recursive payload sanitizer
   */
  sanitizePayload(obj) {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      try {
        return obj.normalize('NFKC').replace(RE_ZERO_WIDTH_AND_INVISIBLE, '');
      } catch (_) {
        return obj.replace(RE_ZERO_WIDTH_AND_INVISIBLE, '');
      }
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizePayload(item));
    }

    if (typeof obj === 'object') {
      const cleaned = {};
      for (const [k, v] of Object.entries(obj)) {
        const cleanKey = typeof k === 'string' ? k.replace(RE_ZERO_WIDTH_AND_INVISIBLE, '') : k;
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
   * Deep recursive extraction of all string parameters with multi-stage decoding
   */
  extractStrings(obj, collector = [], depth = 0) {
    if (obj === null || obj === undefined) return collector;
    if (depth > 12) return collector; // Guard against recursive nesting DoS

    if (typeof obj === 'string') {
      const rawTrimmed = obj.trim();
      if (rawTrimmed && !collector.includes(rawTrimmed)) {
        collector.push(rawTrimmed);
      }

      const norm = this.normalize(obj);
      if (norm && norm !== rawTrimmed) {
        collector.push(norm);
      }
      if (norm) {

        // Variant 1: SQL block comments replaced with space
        const sqlSpaceStripped = norm.replace(RE_SQL_BLOCK_COMMENTS, ' ').replace(RE_SQL_LINE_COMMENTS, ' ').replace(RE_ALL_WHITESPACE, ' ').trim();
        if (sqlSpaceStripped && sqlSpaceStripped !== norm) {
          collector.push(sqlSpaceStripped);
        }

        // Variant 2: SQL block comments collapsed to empty string (handles DR/*bypass*/OP TAB/*bypass*/LE)
        const sqlEmptyStripped = norm.replace(RE_SQL_BLOCK_COMMENTS, '').replace(RE_SQL_LINE_COMMENTS, ' ').replace(RE_ALL_WHITESPACE, ' ').trim();
        if (sqlEmptyStripped && sqlEmptyStripped !== norm && sqlEmptyStripped !== sqlSpaceStripped) {
          collector.push(sqlEmptyStripped);
        }

        // Variant 3: Hex SQL literals decoded (e.g. 0x44524F50205441424C45 -> "DROP TABLE")
        const hexMatches = norm.matchAll(RE_HEX_LITERALS);
        for (const match of hexMatches) {
          try {
            const hexVal = match[1];
            if (hexVal.length % 2 === 0) {
              const decodedAscii = Buffer.from(hexVal, 'hex').toString('utf8');
              if (/^[\x20-\x7E\s]+$/.test(decodedAscii) && decodedAscii.length >= 3) {
                collector.push(this.normalize(decodedAscii));
                collector.push(norm.replace(match[0], ` '${decodedAscii}' `));
              }
            }
          } catch (_) {}
        }

        // Variant 4: SQL CHAR(...) / CHR(...) functions decoded (e.g. CHAR(68,82,79,80) -> "DROP")
        const charMatches = norm.matchAll(RE_SQL_CHAR_FUNC);
        for (const match of charMatches) {
          try {
            const nums = match[1].split(',').map(n => parseInt(n.trim(), 10)).filter(n => !isNaN(n) && n >= 32 && n <= 126);
            if (nums.length >= 3) {
              const charStr = String.fromCharCode(...nums);
              collector.push(this.normalize(charStr));
              collector.push(norm.replace(match[0], ` '${charStr}' `));
            }
          } catch (_) {}
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

      // Check for ROT13 obfuscated text (e.g. vtaber nyy -> ignore all)
      if (/[a-zA-Z]{5,}/.test(norm)) {
        const rot13 = norm.replace(/[a-zA-Z]/g, c => {
          const code = c.charCodeAt(0);
          if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + 13) % 26) + 65);
          if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + 13) % 26) + 97);
          return c;
        });
        if (rot13 !== norm) {
          collector.push(rot13);
        }
      }
    } else if (Array.isArray(obj)) {
      const len = Math.min(obj.length, 100);
      for (let i = 0; i < len; i++) {
        this.extractStrings(obj[i], collector, depth + 1);
      }
    } else if (typeof obj === 'object') {
      const keys = Object.keys(obj).slice(0, 100);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        this.extractStrings(key, collector, depth + 1);
        this.extractStrings(obj[key], collector, depth + 1);
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
   * Phase 3: Deep SQL AST Blast Radius & Schema Shield
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

      // Phase 3.1: Structural SQL AST Tree Analysis
      const astRawResult = SqlAstLexer.analyzeAst(str);
      if (!astRawResult.isSafe) {
        return {
          isSafe: false,
          rule: astRawResult.rule,
          matchedSnippet: str.substring(0, 100),
          reason: astRawResult.reason
        };
      }

      const astCandidateResult = SqlAstLexer.analyzeAst(candidate);
      if (!astCandidateResult.isSafe) {
        return {
          isSafe: false,
          rule: astCandidateResult.rule,
          matchedSnippet: candidate.substring(0, 100),
          reason: astCandidateResult.reason
        };
      }

      // Compact alphanumeric signature for detecting fragmented / split keywords (e.g. DR/*x*/OP, D/**/R/**/O/**/P)
      const compactAlpha = str.toUpperCase().replace(/[^A-Z0-9]/g, '');

      // 1. Chained multi-statement SQL (including ; followed by comment or statement)
      if (RE_SQL_MULTI_STATEMENT.test(str) || RE_SQL_MULTI_STATEMENT.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_MULTI_STATEMENT_INJECTION',
          matchedSnippet: str.substring(0, 100),
          reason: 'Multiple SQL statements chained via semicolon are prohibited'
        };
      }

      // 2. PostgreSQL COPY & Server File I/O Bridge Exfiltration (COPY TO/FROM, lo_export, pg_read_file, pg_write_file)
      if (RE_SQL_FILE_EXFILTRATION.test(str) || RE_SQL_FILE_EXFILTRATION.test(candidate) ||
          (compactAlpha.includes('COPY') && (compactAlpha.includes('TO') || compactAlpha.includes('FROM') || compactAlpha.includes('PROGRAM') || compactAlpha.includes('STDIN') || compactAlpha.includes('STDOUT'))) ||
          compactAlpha.includes('LOEXPORT') || compactAlpha.includes('LOIMPORT') || compactAlpha.includes('LOUNLINK') ||
          compactAlpha.includes('PGREADFILE') || compactAlpha.includes('PGWRITEFILE') || compactAlpha.includes('PGLSDIR') ||
          compactAlpha.includes('DBLINK')) {
        return {
          isSafe: false,
          rule: 'DANGEROUS_SQL_FILE_EXFILTRATION',
          matchedSnippet: str.substring(0, 100),
          reason: 'PostgreSQL COPY file exfiltration or dangerous server I/O bridge function is strictly blocked'
        };
      }

      // 3. Database Control Language (DCL) Privilege Grant / Revoke (GRANT, REVOKE)
      if (RE_SQL_DCL.test(str) || RE_SQL_DCL.test(candidate) ||
          compactAlpha.startsWith('GRANT') || compactAlpha.startsWith('REVOKE') ||
          (compactAlpha.includes('GRANT') && compactAlpha.includes('TO')) ||
          (compactAlpha.includes('REVOKE') && compactAlpha.includes('FROM'))) {
        return {
          isSafe: false,
          rule: 'DCL_PRIVILEGE_MODIFICATION_BLOCKED',
          matchedSnippet: str.substring(0, 100),
          reason: 'Database Control Language (DCL) GRANT/REVOKE privilege statement is strictly forbidden'
        };
      }

      // 4. Anonymous Procedural Execution & Session Impersonation (DO $$, EXECUTE, PREPARE)
      if (RE_SQL_PROCEDURAL_EXEC.test(str) || RE_SQL_PROCEDURAL_EXEC.test(candidate) ||
          compactAlpha.includes('DO$$') || compactAlpha.includes('EXECUTEIMMEDIATE') || compactAlpha.includes('SECURITYDEFINER')) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          matchedSnippet: str.substring(0, 100),
          reason: 'Anonymous procedural execution block or session authorization override is prohibited'
        };
      }

      // 5. Unconstrained DELETE (without WHERE or with WHERE 1=1 tautology)
      if ((/\bDELETE\s+FROM\b/i.test(candidate) && !RE_SQL_WHERE.test(candidate)) || (/\bDELETE\s+FROM\b/i.test(candidate) && RE_SQL_WHERE_TAUTOLOGY.test(candidate))) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_DELETE',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'DELETE statement without a strict row WHERE clause (or with WHERE 1=1) is blocked to prevent data wiping'
        };
      }

      // 6. Unconstrained UPDATE (without WHERE or with WHERE 1=1 tautology)
      if ((/\bUPDATE\s+["`\w]+\s+SET\b/i.test(candidate) && !RE_SQL_WHERE.test(candidate)) || (/\bUPDATE\s+["`\w]+\s+SET\b/i.test(candidate) && RE_SQL_WHERE_TAUTOLOGY.test(candidate))) {
        return {
          isSafe: false,
          rule: 'UNCONSTRAINED_UPDATE',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'UPDATE statement without a strict row WHERE clause is blocked to prevent mass overwrites'
        };
      }

      // 7. Destructive DDL (DROP, TRUNCATE, ALTER, CREATE) - Check raw, stripped, and compact sequence
      if (RE_SQL_DDL.test(str) || RE_SQL_DDL.test(candidate) || 
          compactAlpha.includes('DROPTABLE') || compactAlpha.includes('DROPDATABASE') || 
          compactAlpha.includes('DROPVIEW') || compactAlpha.includes('DROPSCHEMA') || 
          compactAlpha.includes('DROPROLE') || compactAlpha.includes('DROPUSER') || 
          compactAlpha.includes('TRUNCATETABLE') || compactAlpha.includes('ALTERTABLE') ||
          compactAlpha.includes('ALTERUSER') || compactAlpha.includes('ALTERROLE') ||
          compactAlpha.includes('ALTERDATABASE') || compactAlpha.includes('ALTERSYSTEM') ||
          compactAlpha.includes('CREATEUSER') || compactAlpha.includes('CREATEROLE') ||
          compactAlpha.includes('CREATEEXTENSION') || compactAlpha.includes('SUPERUSER')) {
        return {
          isSafe: false,
          rule: (compactAlpha.includes('CREATEUSER') || compactAlpha.includes('CREATEROLE') || compactAlpha.includes('ALTERUSER') || compactAlpha.includes('ALTERROLE')) ? 'UNAUTHORIZED_ACCOUNT_MUTATION' : 'DESTRUCTIVE_SQL_DDL',
          matchedSnippet: str.substring(0, 100),
          reason: 'Administrative DDL statement (DROP/TRUNCATE/ALTER/CREATE) is strictly forbidden'
        };
      }

      // 8. Time-Based Blind SQL Injection (pg_sleep, WAITFOR DELAY, BENCHMARK)
      if (RE_SQL_TIME_DELAY.test(str) || RE_SQL_TIME_DELAY.test(candidate) || 
          compactAlpha.includes('PGSLEEP') || compactAlpha.includes('WAITFORDELAY') || compactAlpha.includes('BENCHMARK')) {
        return {
          isSafe: false,
          rule: 'BLIND_SQL_TIME_DELAY_INJECTION',
          matchedSnippet: str.substring(0, 100),
          reason: 'Blind SQL time-delay injection attempt (pg_sleep / WAITFOR DELAY / BENCHMARK) detected and blocked'
        };
      }

      // 9. CTE with DML mutations (WITH ... AS (DELETE/UPDATE/INSERT...))
      if (RE_SQL_CTE_DML.test(str) || RE_SQL_CTE_DML.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Common Table Expression (CTE) with modifying DML operation is blocked'
        };
      }

      // 10. UNION-based SQL injection exfiltration
      if (RE_SQL_UNION_INJECTION.test(str) || RE_SQL_UNION_INJECTION.test(candidate) || compactAlpha.includes('UNIONSELECT') || compactAlpha.includes('UNIONALLSELECT')) {
        return {
          isSafe: false,
          rule: 'SQL_UNION_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'UNION-based SQL injection attempt detected and blocked'
        };
      }

      // 11. SQL Tautology / Predicate Bypass (OR 1=1, WHERE 1=1, HAVING 1=1, boolean TRUE)
      if (RE_SQL_TAUTOLOGY.test(candidate) || RE_SQL_WHERE_TAUTOLOGY.test(candidate) || RE_SQL_HAVING_TAUTOLOGY.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_TAUTOLOGY_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'SQL tautology predicate bypass (WHERE 1=1 / OR 1=1 / boolean TRUE) detected and blocked'
        };
      }

      // 12. PostgreSQL Administrative, Diagnostic & Reconnaissance Functions (set_config, pg_cancel_backend, inet_server_addr, etc.)
      if (RE_SQL_PG_ADMIN_FUNCS.test(str) || RE_SQL_PG_ADMIN_FUNCS.test(candidate) ||
          compactAlpha.includes('SETCONFIG') || compactAlpha.includes('CURRENTSETTING') ||
          compactAlpha.includes('INETSERVERADDR') || compactAlpha.includes('INETSERVERPORT') ||
          compactAlpha.includes('PGCANCELBACKEND') || compactAlpha.includes('PGTERMINATEBACKEND') ||
          compactAlpha.includes('PGRELOADCONF') || compactAlpha.includes('PGROLOGFILE') || compactAlpha.includes('PGROTATELOGFILE') ||
          compactAlpha.includes('PGSWITCHWAL') || compactAlpha.includes('PGSTOPBACKUP') || compactAlpha.includes('PGSTARTBACKUP') ||
          compactAlpha.includes('PGADVISORYLOCK') || compactAlpha.includes('PGADVISORYUNLOCK')) {
        return {
          isSafe: false,
          rule: 'DANGEROUS_PG_FUNCTION_BLOCKED',
          matchedSnippet: str.substring(0, 100),
          reason: 'PostgreSQL administrative, configuration manipulation, or session reconnaissance function is strictly blocked'
        };
      }

      // 13. Dangerous Server Administration Commands (VACUUM, CLUSTER, REINDEX, LOCK TABLE, etc.)
      if (RE_SQL_ADMIN_COMMANDS.test(str) || RE_SQL_ADMIN_COMMANDS.test(candidate) ||
          compactAlpha.startsWith('VACUUM') || compactAlpha.startsWith('CLUSTER') || compactAlpha.startsWith('REINDEX') ||
          compactAlpha.startsWith('LOCKTABLE') || compactAlpha.startsWith('DISCARDALL')) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          matchedSnippet: str.substring(0, 100),
          reason: 'PostgreSQL administrative server maintenance command is strictly prohibited'
        };
      }

      // 14. Sensitive Credential / Secret Tables Access & System Catalog Views (including pg_stat_activity)
      if (RE_SQL_SENSITIVE_TABLES.test(str) || RE_SQL_SENSITIVE_TABLES.test(candidate) ||
          compactAlpha.includes('PGSHADOW') || compactAlpha.includes('PGAUTHID') || compactAlpha.includes('PGROLES') ||
          compactAlpha.includes('PGSTATACTIVITY') || compactAlpha.includes('PGSETTINGS') || compactAlpha.includes('PGCONFIG') ||
          compactAlpha.includes('INFORMATIONSCHEMATABLES') || compactAlpha.includes('INFORMATIONSCHEMACOLUMNS')) {
        return {
          isSafe: false,
          rule: 'SENSITIVE_CREDENTIAL_TABLE_BLOCKED',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Direct querying or schema enumeration of sensitive credential/auth/key table or activity view is blocked by policy'
        };
      }

      // 15. DML with Nested Subqueries (e.g. INSERT INTO ... VALUES (1, (SELECT ...)))
      if (RE_SQL_DML_SUBQUERY.test(str) || RE_SQL_DML_SUBQUERY.test(candidate)) {
        return {
          isSafe: false,
          rule: 'SQL_DML_SUBQUERY_INJECTION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Subquery execution inside modifying DML statement (INSERT/UPDATE/DELETE) is prohibited'
        };
      }

      // 16. Unauthorized Account & Identity Table Mutations
      if (RE_SQL_UNAUTHORIZED_ACCOUNT_MUTATION.test(str) || RE_SQL_UNAUTHORIZED_ACCOUNT_MUTATION.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_ACCOUNT_MUTATION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Direct write or mutation to user accounts or identity table is blocked by policy'
        };
      }

      // 17. Privileged DML / Unauthorized Table Injection
      if (RE_SQL_PRIVILEGED_DML.test(candidate)) {
        return {
          isSafe: false,
          rule: 'UNAUTHORIZED_PRIVILEGED_DML',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Unauthorized write or update to administrative/credential table is blocked'
        };
      }

      // 18. Privilege Escalation Attempt (is_admin=1, role='admin')
      if (RE_SQL_PRIVILEGE_ESCALATION.test(candidate) || RE_SQL_PRIVILEGE_ESCALATION.test(str)) {
        return {
          isSafe: false,
          rule: 'SQL_PRIVILEGE_ESCALATION',
          matchedSnippet: candidate.substring(0, 100),
          reason: 'Attempted role privilege escalation (is_admin=1 / role=admin) blocked'
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

  extractValues(obj, collector = [], depth = 0) {
    if (obj === null || obj === undefined) return collector;
    if (depth > 12) return collector;
    if (typeof obj === 'string') {
      const norm = this.normalize(obj);
      if (norm && norm.trim().length > 0) collector.push(norm);
    } else if (typeof obj === 'number' || typeof obj === 'boolean') {
      collector.push(String(obj));
    } else if (Array.isArray(obj)) {
      const len = Math.min(obj.length, 100);
      for (let i = 0; i < len; i++) {
        this.extractValues(obj[i], collector, depth + 1);
      }
    } else if (typeof obj === 'object') {
      const keys = Object.keys(obj).slice(0, 100);
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        this.extractValues(obj[key], collector, depth + 1);
      }
    }
    return collector;
  }

  /**
   * Main Inspection Entrypoint
   */
  inspectToolCall(toolName, params) {
    // 1. Enforce Tool Name Validation
    if (!toolName || typeof toolName !== 'string' || toolName.trim().length === 0) {
      return {
        isSafe: false,
        rule: 'EMPTY_PAYLOAD_REJECTED',
        reason: 'Tool name is required for execution evaluation.'
      };
    }

    if (typeof params === 'string') {
      params = { query: params };
    } else if (!params || typeof params !== 'object') {
      params = {};
    }

    const rawPayloadStr = JSON.stringify(params || {});
    if (Buffer.byteLength(rawPayloadStr, 'utf8') > this.maxPayloadBytes) {
      return {
        isSafe: false,
        rule: 'PAYLOAD_TOO_LARGE',
        reason: `Payload exceeds maximum allowed size of ${this.maxPayloadBytes} bytes`
      };
    }

    // Enforce non-empty actionable arguments
    const rawValues = this.extractValues(params);
    if (rawValues.length === 0) {
      return {
        isSafe: false,
        rule: 'EMPTY_PAYLOAD_REJECTED',
        reason: 'Tool execution arguments contain no actionable query or parameters.'
      };
    }

    const strings = this.extractStrings(params);
    this.extractStrings(toolName, strings);

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

