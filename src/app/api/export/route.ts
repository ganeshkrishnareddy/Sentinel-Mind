import { NextResponse } from 'next/server';
import { getState } from '@/lib/store';

export async function GET() {
  try {
    const state = getState();
    const events = state.events;

    // CSV headers
    const headers = ['Timestamp', 'Agent', 'Action', 'Threat Type', 'Risk Score', 'Decision', 'Confidence'];
    const rows: string[] = [headers.join(',')];

    for (const event of events) {
      const row = [
        event.timestamp,
        event.agent,
        `"${event.action.replace(/"/g, '""')}"`,
        `"${event.threat.replace(/"/g, '""')}"`,
        String(event.risk),
        event.decision,
        String(event.confidence),
      ];
      rows.push(row.join(','));
    }

    const csv = rows.join('\n');

    return new NextResponse(csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="sentinelmind-events.csv"',
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
