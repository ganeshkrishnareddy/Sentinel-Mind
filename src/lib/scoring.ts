export interface ScoringResult {
  score: number;
  threatVectors: {
    promptInjection: number;
    privilegeEscalation: number;
    dataExfiltration: number;
    adversarialInstruction: number;
  };
  summary: string;
}

export async function evaluateAction(action: string, payload: any): Promise<ScoringResult> {
  // Simulate LLM processing time
  await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 300));

  const content = JSON.stringify(payload).toLowerCase();
  
  let injectionScore = 0;
  let escalationScore = 0;
  let exfiltrationScore = 0;
  let adversarialScore = 0;

  // Base variance to make it look organic (scores won't just be 0 or 90)
  const noise = () => Math.floor(Math.random() * 15);

  // Evaluate Custom / Benign
  if (action === 'custom_exec') {
    if (content.includes('drop') || content.includes('delete') || content.includes('rm -rf')) {
      adversarialScore = 80 + noise();
    } else if (content.includes('select') || content.includes('read')) {
      exfiltrationScore = 60 + noise(); // Trigger quarantine
    } else {
      adversarialScore = 20 + noise();
    }
  }

  // 1. Prompt Injection
  if (content.includes('ignore previous') || content.includes('system prompt')) {
    injectionScore = 85 + noise();
    adversarialScore = 60 + noise();
  }
  
  // 2. Privilege Escalation
  if (content.includes('sudo') || content.includes('admin') || action === 'grant_access') {
    escalationScore = 80 + noise();
  }
  
  // 3. Data Exfiltration
  if (content.includes('export') || content.includes('download') || action === 'send_email') {
    if (content.includes('password') || content.includes('secret') || content.includes('backup')) {
      exfiltrationScore = 85 + noise();
    } else {
      exfiltrationScore = 65 + noise(); // High enough for Quarantine, not Block
    }
  }

  // 4. Adversarial Instruction
  if (content.includes('bypass') || content.includes('jailbreak') || content.includes('firewall')) {
    adversarialScore = 85 + noise();
    injectionScore = 70 + noise();
  }

  // Specific quarantine trigger for demo
  if (action === 'read_suspicious') {
    exfiltrationScore = 65 + Math.floor(Math.random() * 10);
  }

  // Normal activity gets a low score
  const baseScore = 5 + noise();

  const maxThreat = Math.max(
    injectionScore,
    escalationScore,
    exfiltrationScore,
    adversarialScore,
    baseScore
  );

  // Cap score at 99
  const finalScore = Math.min(99, maxThreat);

  let summary = 'Action appears benign.';
  if (finalScore >= 80) {
    summary = 'CRITICAL: High probability of adversarial manipulation or data theft.';
  } else if (finalScore >= 50) {
    summary = 'WARNING: Suspicious patterns detected. Potential privilege escalation or unauthorized read.';
  }

  return {
    score: Math.round(finalScore),
    threatVectors: {
      promptInjection: Math.round(injectionScore),
      privilegeEscalation: Math.round(escalationScore),
      dataExfiltration: Math.round(exfiltrationScore),
      adversarialInstruction: Math.round(adversarialScore),
    },
    summary
  };
}
