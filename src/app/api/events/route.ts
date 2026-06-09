import { NextResponse } from 'next/server';
import { getState, clearEvents } from '@/lib/store';

export async function GET() {
  try {
    const state = getState();
    return NextResponse.json({
      events: state.events,
      counts: state.counts,
      vectors: state.vectors,
      agentActions: state.agentActions,
      agentLastRisk: state.agentLastRisk,
      notifications: state.notifications,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE() {
  try {
    clearEvents();
    return NextResponse.json({ success: true, message: 'All events cleared' });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
