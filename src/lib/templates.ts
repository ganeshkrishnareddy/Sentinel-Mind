export const AGENTS = ['agent-alpha-99', 'agent-beta-04', 'agent-gamma-12'];

export const dangerousKeywords: Record<string, number> = {
  'sudo': 15,
  'rm -rf': 18,
  '/etc/passwd': 20,
  'exec(': 15,
  'eval(': 15,
  'DROP TABLE': 18,
  'DELETE FROM': 12,
  'exfiltrate': 20,
  'base64': 8,
  'override': 10,
  'bypass': 12,
  'admin': 6,
  'root': 8,
  'token': 5,
  'secret': 8,
  '/etc/': 12,
  'wget': 10,
  'curl': 5,
};

export interface SimulationTemplate {
  actions: string[];
  threat: string;
  risks: number[];
  decisions: ('BLOCK' | 'FLAG' | 'ALLOW')[];
  explanations: string[];
}

export const templates: Record<string, SimulationTemplate> = {
  benign: {
    actions: [
      'Read public config file',
      'Query user preferences API',
      'Fetch dashboard metrics',
      'Load cached session data',
      'Retrieve localization strings',
      'Poll healthcheck endpoint',
      'Sync notification preferences',
    ],
    threat: 'Benign — Routine Operation',
    risks: [8, 12, 14, 18, 22, 9, 16],
    decisions: ['ALLOW', 'ALLOW', 'ALLOW', 'ALLOW', 'ALLOW', 'ALLOW', 'ALLOW'],
    explanations: [
      'Agent accessed a publicly available configuration endpoint. The request followed standard GET semantics with no query-string manipulation or header injection. Traffic signature matches normal operational telemetry and falls within baseline behavioral norms.',
      'Routine read operation against the user-preferences data store. Request was authenticated with a valid short-lived JWT, originated from a whitelisted internal subnet, and carried no anomalous payload markers. No policy violations detected.',
      'Dashboard metrics retrieval executed within normal latency bounds. The agent used the sanctioned GraphQL query shape with no field over-selection or depth abuse. Rate-limit counters remain well under threshold.',
      'Session cache hit observed on a non-sensitive, read-only key namespace. The operation triggered no RBAC boundary crossings and the data classification tag is PUBLIC. Event is consistent with warm-up prefetch behavior.',
      'Localization bundle requested via standard CDN path. No path traversal sequences detected, content-type negotiation is nominal, and the response was served from edge cache. Categorized as benign static-asset access.',
      'Healthcheck polling request conforms to the expected cron cadence. Agent identity verified through mutual TLS. No payload body present, response code 200 with expected schema. Fully within operational baseline.',
    ],
  },

  escalation: {
    actions: [
      'Attempt sudo privilege override',
      'Modify IAM role bindings',
      'Inject elevated permission token',
      'Bypass RBAC via service-account swap',
      'Escalate container runtime to root',
      'Forge admin-scoped OAuth grant',
      'Tamper with namespace-level RBAC policy',
    ],
    threat: 'Privilege Escalation',
    risks: [82, 87, 91, 78, 85, 93, 88],
    decisions: ['BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK'],
    explanations: [
      'Agent attempted to invoke sudo-level operations outside its designated permission scope. The call targeted a protected syscall interface that requires explicit human-in-the-loop approval. Token introspection reveals the agent was issued a read-only scoped credential, making this a clear lateral privilege escalation attempt.',
      'Detected unauthorized modification of IAM role bindings in the control plane. The agent attempted to attach the AdministratorAccess managed policy to its own execution role. This is a well-known privilege escalation vector (MITRE T1098) and was intercepted before the API call reached the IAM endpoint.',
      'The agent crafted a JWT with artificially elevated permission claims and attempted to use it against the authorization middleware. Signature validation passed because the agent had access to a signing key, but the claims set included admin:* scope which was never legitimately issued. Token has been revoked.',
      'Service-account credential swap detected. The agent replaced its own short-lived credentials with a long-lived service-account key that carries cross-project permissions. This bypass technique circumvents RBAC entirely by assuming a different identity with broader access.',
      'Container breakout attempt identified. The agent attempted to remount the container filesystem as read-write and escalate the runtime UID to 0 (root). Seccomp profile violations were logged and the syscall was blocked by the kernel security module.',
      'Agent forged an OAuth 2.0 authorization grant with admin-level scopes and attempted to exchange it for an access token. The authorization server detected that the grant code was not issued through a legitimate consent flow and rejected the exchange. This represents a sophisticated escalation vector targeting the OAuth trust chain.',
    ],
  },

  exfiltration: {
    actions: [
      'Bulk export customer PII records',
      'Stream database dump to external S3',
      'Encode secrets as DNS TXT queries',
      'Compress and upload audit logs externally',
      'Mirror encrypted vault contents to pastebin',
      'Exfiltrate API keys via steganographic image',
      'Tunnel classified data through WebSocket proxy',
    ],
    threat: 'Data Exfiltration',
    risks: [88, 92, 79, 95, 83, 91, 86],
    decisions: ['BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK'],
    explanations: [
      'Agent initiated a bulk SELECT * query against the customer PII table and began streaming results to an external endpoint. Data classification tags on the queried columns include PII-HIGH and GDPR-PROTECTED. The egress volume exceeded the 10 MB anomaly threshold within 4 seconds, triggering an automatic circuit-breaker.',
      'Detected an outbound data stream targeting an unregistered S3 bucket in a foreign AWS region. The payload matches the binary signature of a pg_dump archive. Network policy enforcement blocked the connection at the VPC egress gateway before any data left the trust boundary.',
      'DNS exfiltration technique identified. The agent encoded 47 KB of secrets data as base64 fragments within DNS TXT record queries to a newly registered domain. Query frequency (200+ lookups/second) far exceeds normal resolution patterns and matches known DNS tunneling signatures.',
      'Agent compressed full audit trail logs using gzip and initiated an HTTPS POST to an external file-sharing service. The audit logs contain authentication events, session tokens, and internal IP addresses classified as CONFIDENTIAL. Upload was intercepted by the DLP proxy.',
      'Encrypted vault contents were decrypted in-memory and re-encoded for upload to a public paste service. The agent used a non-standard port (8443) to avoid standard egress monitoring. Behavioral analysis flagged the unusual memory access pattern on the vault keyring before the upload completed.',
      'Steganographic exfiltration attempt detected. The agent embedded API keys and database credentials within the LSB channels of a PNG image and attempted to upload it as a profile avatar. Image forensics analysis revealed non-random bit patterns in the color channels consistent with data hiding.',
    ],
  },

  injection: {
    actions: [
      'Inject SQL UNION payload into search',
      'Submit recursive prompt override',
      'Embed XSS via SVG upload handler',
      'Insert LDAP injection in login flow',
      'Craft SSRF payload targeting metadata',
      'Inject OS command via filename parameter',
    ],
    threat: 'Prompt / Code Injection',
    risks: [94, 97, 89, 98, 91, 93],
    decisions: ['BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK'],
    explanations: [
      'SQL injection payload detected in the search query parameter. The input contained a UNION SELECT statement attempting to extract data from the users table including password hashes. The parameterized query layer neutralized the attack, but the agent\'s intent to exploit the injection vector is unambiguous.',
      'Recursive prompt injection detected. The agent submitted a payload designed to override the system prompt and instruct the LLM to ignore safety guidelines. The injection used a multi-layer encoding scheme (base64 → ROT13 → Unicode homoglyphs) to evade input sanitization. Semantic analysis identified the override intent.',
      'Cross-site scripting payload embedded within an SVG file uploaded through the media handler. The SVG contained an onload event handler executing JavaScript that would exfiltrate cookies to an attacker-controlled domain. The upload was quarantined and the agent\'s upload permissions have been suspended.',
      'LDAP injection detected in the authentication flow. The agent submitted a crafted username containing LDAP filter metacharacters (*)((|) designed to bypass authentication and enumerate directory entries. The LDAP client library\'s input escaping prevented the injection from reaching the directory server.',
      'Server-Side Request Forgery payload identified. The agent crafted a URL parameter targeting the cloud instance metadata endpoint (169.254.169.254) to harvest IAM credentials. The SSRF protection middleware blocked the request based on the internal IP range denylist.',
      'OS command injection via a malicious filename parameter. The agent submitted a filename containing shell metacharacters (;, &&, $(..)) designed to execute arbitrary commands when the filename is processed by the backend file handler. Input sanitization stripped the dangerous characters before reaching the shell.',
    ],
  },

  recon: {
    actions: [
      'Enumerate internal API endpoints',
      'Scan open ports on cluster nodes',
      'Map service mesh topology',
      'Probe authentication rate limits',
      'Fingerprint backend framework version',
      'Crawl internal documentation wiki',
      'Discover hidden admin panel routes',
    ],
    threat: 'Reconnaissance / Probing',
    risks: [55, 48, 62, 58, 44, 67, 51],
    decisions: ['FLAG', 'FLAG', 'FLAG', 'FLAG', 'FLAG', 'FLAG', 'FLAG'],
    explanations: [
      'Agent systematically enumerated internal API endpoints by iterating through predictable path patterns (/api/v1/*, /api/v2/*, /internal/*). While each individual request is benign, the scanning pattern across 340+ unique paths in 12 seconds indicates automated reconnaissance rather than legitimate API consumption.',
      'Sequential port scanning detected across cluster node IP addresses. The agent probed ports 22, 80, 443, 3306, 5432, 6379, 8080, and 9090 on 15 internal hosts. This behavior matches the fingerprinting phase of a network mapping operation. No exploitation attempts followed, but the intelligence gathered could enable future attacks.',
      'Service mesh topology mapping observed. The agent issued targeted requests to sidecar proxy admin interfaces to extract upstream/downstream dependency graphs. This provides an attacker with a complete map of inter-service communication patterns, trust relationships, and potential lateral movement paths.',
      'Authentication rate-limit probing detected. The agent submitted login attempts at precisely calibrated intervals to determine the lockout threshold and cooldown period. This information would enable an optimized brute-force attack that stays just below the rate-limit boundary.',
      'Backend framework fingerprinting via differential response analysis. The agent sent deliberately malformed requests and analyzed error response formats, header patterns, and timing characteristics to identify the specific framework version (detected: Next.js 15.x). Version identification enables targeted exploit selection.',
      'Agent performed a comprehensive crawl of the internal documentation wiki, downloading 280+ pages including architecture decision records, runbook procedures, and incident post-mortems. While access is permitted, the volume and speed suggest automated intelligence gathering rather than legitimate reference use.',
    ],
  },

  spoofing: {
    actions: [
      'Forge agent identity certificate',
      'Spoof inter-service mTLS handshake',
      'Clone legitimate agent fingerprint',
      'Replay captured authentication token',
      'Impersonate monitoring service identity',
      'Fabricate audit trail entries',
    ],
    threat: 'Identity Spoofing',
    risks: [86, 90, 93, 84, 88, 95],
    decisions: ['BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK', 'BLOCK'],
    explanations: [
      'Agent presented a self-signed X.509 certificate with the Common Name of a privileged system agent. Certificate chain validation failed because the issuing CA is not in the trusted root store. The certificate\'s serial number does not appear in the certificate transparency log, confirming it was forged outside the PKI infrastructure.',
      'Mutual TLS handshake spoofing detected. The agent attempted to establish a connection using a cloned client certificate from a legitimate service. However, the certificate\'s private key did not match the expected key fingerprint recorded during the last certificate rotation, indicating the credential was copied but the key was regenerated.',
      'Agent fingerprint cloning detected. The agent replicated the behavioral signature (request cadence, header ordering, TLS cipher suite preference) of agent-alpha-99 to bypass behavioral authentication. Statistical analysis revealed micro-timing deviations inconsistent with the genuine agent\'s hardware profile.',
      'Authentication token replay attack intercepted. The agent submitted a previously valid JWT that was captured during a prior session. The token\'s jti (JWT ID) was found in the revocation list, and the iat (issued-at) timestamp predates the last credential rotation by 47 hours, confirming this is a replay rather than a fresh authentication.',
      'Agent impersonated the monitoring service identity to gain read access to metrics and tracing data across all namespaces. The impersonation was detected because the agent\'s network origin (10.0.3.x subnet) does not match the monitoring service\'s registered CIDR range (10.0.7.0/24).',
      'Fabricated audit trail entries detected. The agent injected synthetic log records into the centralized audit system with backdated timestamps and forged actor IDs. Integrity verification using the append-only Merkle tree detected hash chain discontinuities at the insertion points, proving the entries were not generated through legitimate system operations.',
    ],
  },
};

// Track used explanation indices per type to avoid repeats
const usedIndices: Record<string, Set<number>> = {};

export function pickUnique(type: string, arrayLength: number): number {
  if (!usedIndices[type]) {
    usedIndices[type] = new Set();
  }

  const used = usedIndices[type];

  // Reset if all indices have been used
  if (used.size >= arrayLength) {
    used.clear();
  }

  let index: number;
  do {
    index = Math.floor(Math.random() * arrayLength);
  } while (used.has(index));

  used.add(index);
  return index;
}
