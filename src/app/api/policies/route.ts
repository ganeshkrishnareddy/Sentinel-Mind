import { NextRequest, NextResponse } from 'next/server';
import { getPolicies, addPolicy, togglePolicy, removePolicy } from '@/lib/store';

export async function GET() {
  try {
    const policies = getPolicies();
    return NextResponse.json({ policies });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name, desc } = body;

    if (!name || !desc) {
      return NextResponse.json(
        { error: 'Missing required fields: name, desc' },
        { status: 400 }
      );
    }

    const policy = addPolicy({ name, desc });
    return NextResponse.json({ success: true, policy });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { id } = body;

    if (typeof id !== 'number') {
      return NextResponse.json(
        { error: 'Missing or invalid field: id (number)' },
        { status: 400 }
      );
    }

    const policy = togglePolicy(id);
    if (!policy) {
      return NextResponse.json(
        { error: `Policy with id ${id} not found` },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true, policy });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const body = await request.json();
    const { id } = body;

    if (typeof id !== 'number') {
      return NextResponse.json(
        { error: 'Missing or invalid field: id (number)' },
        { status: 400 }
      );
    }

    const removed = removePolicy(id);
    if (!removed) {
      return NextResponse.json(
        { error: `Policy with id ${id} not found` },
        { status: 404 }
      );
    }

    return NextResponse.json({ success: true, message: `Policy ${id} removed` });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
