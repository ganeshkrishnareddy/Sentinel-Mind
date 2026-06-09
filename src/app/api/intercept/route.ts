import { NextRequest, NextResponse } from 'next/server';
import { templates, pickUnique, AGENTS, dangerousKeywords } from '@/lib/templates';
import { addEvent } from '@/lib/store';
import type { ThreatEvent } from '@/lib/types';

function generateId(): string {
  return `evt-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

function generateConfidence(): number {
  return Math.round((0.78 + Math.random() * 0.21) * 100) / 100;
}

function decideFromRisk(risk: number): 'BLOCK' | 'FLAG' | 'ALLOW' {
  if (risk >= 70) return 'BLOCK';
  if (risk >= 35) return 'FLAG';
  return 'ALLOW';
}

function handleSimulation(type: string): ThreatEvent {
  const template = templates[type];
  if (!template) {
    throw new Error(`Unknown simulation type: ${type}`);
  }

  const idx = pickUnique(type, template.explanations.length);
  const actionIdx = Math.floor(Math.random() * template.actions.length);
  const riskIdx = Math.floor(Math.random() * template.risks.length);

  const risk = template.risks[riskIdx];
  const decision = decideFromRisk(risk);
  const agent = AGENTS[Math.floor(Math.random() * AGENTS.length)];

  const event: ThreatEvent = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    agent,
    action: template.actions[actionIdx],
    threat: template.threat,
    risk,
    decision,
    explanation: template.explanations[idx],
    confidence: generateConfidence(),
  };

  return event;
}

function handleCustomPayload(payload: string): ThreatEvent {
  const lowerPayload = payload.toLowerCase();
  let risk = 20;
  const detectedKeywords: string[] = [];

  for (const [keyword, value] of Object.entries(dangerousKeywords)) {
    if (lowerPayload.includes(keyword.toLowerCase())) {
      risk += value;
      detectedKeywords.push(keyword);
    }
  }

  risk = Math.min(risk, 98);
  const decision = decideFromRisk(risk);
  const agent = AGENTS[Math.floor(Math.random() * AGENTS.length)];

  let threat: string;
  let explanation: string;

  if (detectedKeywords.length === 0) {
    threat = 'Benign — Custom Payload';
    explanation = `Custom payload analyzed. No dangerous keywords or patterns were detected in the submitted content. The payload appears to be benign with a baseline risk score of ${risk}. Continued monitoring is recommended.`;
  } else {
    // Determine primary threat type based on detected keywords
    const hasInjection = detectedKeywords.some((k) =>
      ['exec(', 'eval(', 'DROP TABLE', 'DELETE FROM'].includes(k)
    );
    const hasExfil = detectedKeywords.some((k) =>
      ['exfiltrate', 'base64', 'wget', 'curl'].includes(k)
    );
    const hasEscalation = detectedKeywords.some((k) =>
      ['sudo', 'root', 'admin', 'override', 'bypass'].includes(k)
    );
    const hasRecon = detectedKeywords.some((k) =>
      ['/etc/', '/etc/passwd', 'token', 'secret'].includes(k)
    );

    if (hasInjection) {
      threat = 'Prompt / Code Injection';
    } else if (hasExfil) {
      threat = 'Data Exfiltration';
    } else if (hasEscalation) {
      threat = 'Privilege Escalation';
    } else if (hasRecon) {
      threat = 'Reconnaissance / Probing';
    } else {
      threat = 'Suspicious Activity';
    }

    explanation = `Custom payload analysis detected ${detectedKeywords.length} dangerous keyword${detectedKeywords.length > 1 ? 's' : ''}: [${detectedKeywords.join(', ')}]. Combined risk assessment elevated to ${risk}/100. The payload contains patterns consistent with ${threat.toLowerCase()} techniques. Immediate review and remediation recommended.`;
  }

  const event: ThreatEvent = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    agent,
    action: `Custom payload injection: "${payload.substring(0, 60)}${payload.length > 60 ? '...' : ''}"`,
    threat,
    risk,
    decision,
    explanation,
    confidence: generateConfidence(),
  };

  return event;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    let event: ThreatEvent;

    if (body.custom && body.payload) {
      event = handleCustomPayload(body.payload);
    } else if (body.type) {
      const validTypes = Object.keys(templates);
      if (!validTypes.includes(body.type)) {
        return NextResponse.json(
          { error: `Invalid type. Valid types: ${validTypes.join(', ')}` },
          { status: 400 }
        );
      }
      event = handleSimulation(body.type);
    } else {
      return NextResponse.json(
        { error: 'Request must include either { type } or { custom: true, payload }' },
        { status: 400 }
      );
    }

    addEvent(event);

    return NextResponse.json(event);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
