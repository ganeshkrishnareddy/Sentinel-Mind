export interface ThreatEvent {
  id: string;
  timestamp: string;
  agent: string;
  action: string;
  threat: string;
  risk: number;
  decision: 'BLOCK' | 'FLAG' | 'ALLOW';
  explanation: string;
  confidence: number;
}

export interface ScoringResult {
  risk: number;
  threat: string;
  decision: 'BLOCK' | 'FLAG' | 'ALLOW';
  explanation: string;
  confidence: number;
}

export interface Policy {
  id: number;
  name: string;
  desc: string;
  status: boolean;
  triggers: number;
  lastTriggered: string | null;
}

export interface UserSession {
  name: string;
  email: string;
  org: string;
  role: string;
}

export interface AppState {
  events: ThreatEvent[];
  counts: { total: number; blocked: number; flagged: number; allowed: number };
  vectors: { injection: number; privilege: number; exfil: number; spoof: number; recon: number; benign: number };
  agentActions: Record<string, number>;
  agentLastRisk: Record<string, number | null>;
  policies: Policy[];
  notifications: Array<{ icon: string; msg: string; time: string; read: boolean }>;
}
