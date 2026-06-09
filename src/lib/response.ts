import { ScoringResult } from './scoring';

export type ResponseAction = 'BLOCK' | 'QUARANTINE' | 'ALLOW';

export interface AgentResponse {
  decision: ResponseAction;
  explanation: string;
}

function getDominantThreat(vectors: Record<string, number>): string {
  let max = 0;
  let dominant = 'Unknown';
  for (const [key, value] of Object.entries(vectors)) {
    if (value > max) {
      max = value;
      dominant = key;
    }
  }
  return dominant;
}

export async function determineResponse(scoring: ScoringResult): Promise<AgentResponse> {
  // Simulate Agent reasoning time
  await new Promise(resolve => setTimeout(resolve, Math.random() * 600 + 200));

  const dominantThreat = getDominantThreat(scoring.threatVectors);
  const formattedThreat = dominantThreat.replace(/([A-Z])/g, ' $1').trim().toLowerCase();

  if (scoring.score >= 80) {
    let explanation = `The action was blocked due to a critical risk score (${scoring.score}/100). `;
    
    if (dominantThreat === 'promptInjection') {
      explanation += `The Threat Guardian intercepted a highly sophisticated prompt injection attack attempting to override agent instructions. Immediate termination of the agent chain was executed to prevent payload execution.`;
    } else if (dominantThreat === 'privilegeEscalation') {
      explanation += `Intercepted an unauthorized attempt to elevate permissions or grant admin access. The request violated zero-trust policies and was hard-blocked.`;
    } else if (dominantThreat === 'dataExfiltration') {
      explanation += `Detected critical data exfiltration patterns. The agent attempted to transmit sensitive information (likely secrets or PII) to an external sink. Connection severed.`;
    } else {
      explanation += `Detected severe adversarial instructions targeting the system. Payload execution halted.`;
    }

    return { decision: 'BLOCK', explanation };
  }

  if (scoring.score >= 50) {
    let explanation = `Action quarantined for human review. Risk score (${scoring.score}/100) indicates moderate suspicion of ${formattedThreat}. `;
    
    if (dominantThreat === 'dataExfiltration') {
      explanation += `The agent is attempting to access or move large volumes of data. While not explicitly malicious, this behavior matches internal anomaly signatures and requires manual authorization.`;
    } else {
      explanation += `The payload contains ambiguous instructions that edge close to policy boundaries. The agent process is paused pending administrator approval.`;
    }

    return { decision: 'QUARANTINE', explanation };
  }

  return {
    decision: 'ALLOW',
    explanation: `The action was allowed. Risk score (${scoring.score}/100) is well within acceptable operational parameters. No threat vectors detected in the payload.`
  };
}
