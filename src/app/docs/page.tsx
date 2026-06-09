import React from 'react';
import Link from 'next/link';

export default function DocsPage() {
  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: 'var(--bg, #090c10)',
      color: 'var(--text, #e6edf3)',
      fontFamily: 'var(--font-sans, system-ui, sans-serif)',
      padding: '40px 20px',
      lineHeight: 1.6
    }}>
      <div style={{ maxWidth: 800, margin: '0 auto' }}>
        <div style={{ marginBottom: 40, borderBottom: '1px solid var(--border, #1e2d3d)', paddingBottom: 20 }}>
          <h1 style={{ fontFamily: 'var(--font-heading, Syne, sans-serif)', fontSize: 36, color: 'var(--accent, #00d4ff)' }}>
            SentinelMind Documentation
          </h1>
          <p style={{ color: 'var(--muted, #7d8590)' }}>Version 2.1.0 • API Reference & Integration Guide</p>
        </div>

        <section style={{ marginBottom: 40 }}>
          <h2 style={{ color: 'var(--blue, #58a6ff)' }}>Getting Started</h2>
          <p>SentinelMind is a lightweight, zero-trust security layer designed for autonomous AI agent systems. To integrate it into your agent pipeline, you simply route all agent actions through the `/api/intercept` endpoint before execution.</p>
        </section>

        <section style={{ marginBottom: 40 }}>
          <h2 style={{ color: 'var(--blue, #58a6ff)' }}>API Endpoints</h2>
          
          <div style={{ backgroundColor: 'var(--surface, #0d1117)', border: '1px solid var(--border, #1e2d3d)', borderRadius: 8, padding: 20, marginBottom: 20 }}>
            <h3><span style={{ color: 'var(--accent, #00d4ff)', fontFamily: 'var(--font-mono, monospace)' }}>POST</span> /api/intercept</h3>
            <p>Analyzes an intended agent action and returns a decision (BLOCK, QUARANTINE, ALLOW) along with a risk score.</p>
            <h4 style={{ marginTop: 20 }}>Request Body (Custom Payload)</h4>
            <pre style={{ backgroundColor: '#000', padding: 12, borderRadius: 6, overflowX: 'auto', color: '#a5d6ff' }}>
{`{
  "custom": true,
  "payload": "string"
}`}
            </pre>
            <h4 style={{ marginTop: 20 }}>Response (ThreatEvent)</h4>
            <pre style={{ backgroundColor: '#000', padding: 12, borderRadius: 6, overflowX: 'auto', color: '#7ee787' }}>
{`{
  "id": "evt-123",
  "timestamp": "2026-06-09T...",
  "agent": "agent-alpha",
  "action": "Custom payload injection...",
  "threat": "Prompt Injection",
  "risk": 85,
  "decision": "BLOCK",
  "explanation": "Custom payload analysis detected dangerous keywords...",
  "confidence": 0.94
}`}
            </pre>
          </div>

          <div style={{ backgroundColor: 'var(--surface, #0d1117)', border: '1px solid var(--border, #1e2d3d)', borderRadius: 8, padding: 20 }}>
            <h3><span style={{ color: 'var(--accent, #00d4ff)', fontFamily: 'var(--font-mono, monospace)' }}>GET</span> /api/events</h3>
            <p>Returns the full in-memory state store, including all tracked events, dashboard statistics, threat vector tallies, and active notifications.</p>
          </div>
        </section>

        <section style={{ marginBottom: 40 }}>
          <h2 style={{ color: 'var(--blue, #58a6ff)' }}>Risk Scoring Engine</h2>
          <p>Risk is evaluated on a scale of 0 to 100.</p>
          <ul style={{ listStyleType: 'disc', paddingLeft: 20 }}>
            <li><strong>ALLOW (0-34)</strong>: Normal operational boundaries. Action is cleared for execution.</li>
            <li><strong>QUARANTINE (35-69)</strong>: Suspicious behavior. Action is halted pending human review.</li>
            <li><strong>BLOCK (70-100)</strong>: Verified malicious intent. Action is aggressively terminated.</li>
          </ul>
        </section>

        <Link href="/" style={{ display: 'inline-block', marginTop: 20, color: 'var(--bg, #090c10)', backgroundColor: 'var(--accent, #00d4ff)', padding: '8px 16px', borderRadius: 4, textDecoration: 'none', fontWeight: 'bold' }}>
          ← Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
