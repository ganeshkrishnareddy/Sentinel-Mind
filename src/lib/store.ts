import type { ThreatEvent, Policy, AppState } from './types';

const defaultPolicies: Policy[] = [
  {
    id: 1,
    name: 'Zero-Tolerance Exfiltration',
    desc: 'Immediately block any data exfiltration attempt regardless of confidence level. All outbound data transfers to unregistered endpoints are terminated.',
    status: true,
    triggers: 0,
    lastTriggered: null,
  },
  {
    id: 2,
    name: 'Privilege Escalation Guard',
    desc: 'Block any agent attempting to elevate permissions beyond its assigned RBAC scope. Includes sudo overrides, IAM modifications, and token forging.',
    status: true,
    triggers: 0,
    lastTriggered: null,
  },
  {
    id: 3,
    name: 'Suspicious Recon Quarantine',
    desc: 'Flag and quarantine agents exhibiting reconnaissance behavior such as port scanning, endpoint enumeration, or service topology mapping.',
    status: true,
    triggers: 0,
    lastTriggered: null,
  },
];

let events: ThreatEvent[] = [];
let counts = { total: 0, blocked: 0, flagged: 0, allowed: 0 };
let vectors = { injection: 0, privilege: 0, exfil: 0, spoof: 0, recon: 0, benign: 0 };
let agentActions: Record<string, number> = {};
let agentLastRisk: Record<string, number | null> = {};
let policies: Policy[] = [...defaultPolicies];
let notifications: Array<{ icon: string; msg: string; time: string; read: boolean }> = [];
let nextPolicyId = 4;

function mapThreatToVector(threat: string): keyof typeof vectors | null {
  const lower = threat.toLowerCase();
  if (lower.includes('injection') || lower.includes('prompt')) return 'injection';
  if (lower.includes('escalation') || lower.includes('privilege')) return 'privilege';
  if (lower.includes('exfiltration') || lower.includes('exfil')) return 'exfil';
  if (lower.includes('spoof') || lower.includes('identity')) return 'spoof';
  if (lower.includes('recon') || lower.includes('probing')) return 'recon';
  if (lower.includes('benign') || lower.includes('routine')) return 'benign';
  return null;
}

function getNotificationIcon(decision: string): string {
  switch (decision) {
    case 'BLOCK': return '🛑';
    case 'FLAG': return '⚠️';
    case 'ALLOW': return '✅';
    default: return '📋';
  }
}

export function getState(): AppState {
  return {
    events: [...events],
    counts: { ...counts },
    vectors: { ...vectors },
    agentActions: { ...agentActions },
    agentLastRisk: { ...agentLastRisk },
    policies: policies.map((p) => ({ ...p })),
    notifications: notifications.map((n) => ({ ...n })),
  };
}

export function addEvent(event: ThreatEvent): void {
  events.unshift(event);

  // Update counts
  counts.total += 1;
  switch (event.decision) {
    case 'BLOCK': counts.blocked += 1; break;
    case 'FLAG': counts.flagged += 1; break;
    case 'ALLOW': counts.allowed += 1; break;
  }

  // Update vectors
  const vectorKey = mapThreatToVector(event.threat);
  if (vectorKey) {
    vectors[vectorKey] += 1;
  }

  // Update agent stats
  agentActions[event.agent] = (agentActions[event.agent] || 0) + 1;
  agentLastRisk[event.agent] = event.risk;

  // Update policy triggers
  for (const policy of policies) {
    if (!policy.status) continue;
    const pLower = policy.name.toLowerCase();
    const tLower = event.threat.toLowerCase();

    const shouldTrigger =
      (pLower.includes('exfiltration') && tLower.includes('exfiltration')) ||
      (pLower.includes('escalation') && tLower.includes('escalation')) ||
      (pLower.includes('recon') && tLower.includes('recon'));

    if (shouldTrigger) {
      policy.triggers += 1;
      policy.lastTriggered = event.timestamp;
    }
  }

  // Add notification
  notifications.unshift({
    icon: getNotificationIcon(event.decision),
    msg: `${event.decision}: ${event.action} by ${event.agent} (risk: ${event.risk})`,
    time: event.timestamp,
    read: false,
  });

  // Keep notifications capped at 50
  if (notifications.length > 50) {
    notifications = notifications.slice(0, 50);
  }
}

export function clearEvents(): void {
  events = [];
  counts = { total: 0, blocked: 0, flagged: 0, allowed: 0 };
  vectors = { injection: 0, privilege: 0, exfil: 0, spoof: 0, recon: 0, benign: 0 };
  agentActions = {};
  agentLastRisk = {};
  notifications = [];
}

export function getPolicies(): Policy[] {
  return policies.map((p) => ({ ...p }));
}

export function addPolicy(p: { name: string; desc: string }): Policy {
  const newPolicy: Policy = {
    id: nextPolicyId++,
    name: p.name,
    desc: p.desc,
    status: true,
    triggers: 0,
    lastTriggered: null,
  };
  policies.push(newPolicy);
  return { ...newPolicy };
}

export function togglePolicy(id: number): Policy | null {
  const policy = policies.find((p) => p.id === id);
  if (!policy) return null;
  policy.status = !policy.status;
  return { ...policy };
}

export function removePolicy(id: number): boolean {
  const index = policies.findIndex((p) => p.id === id);
  if (index === -1) return false;
  policies.splice(index, 1);
  return true;
}
