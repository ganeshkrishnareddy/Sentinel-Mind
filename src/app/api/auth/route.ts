import { NextRequest, NextResponse } from 'next/server';
import type { UserSession } from '@/lib/types';

const DEMO_EMAIL = 'admin@sentinelmind.io';
const DEMO_PASSWORD = 'sentinel2026';

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, email, password, name, org, role } = body;

    if (!action || !email || !password) {
      return NextResponse.json(
        { error: 'Missing required fields: action, email, password' },
        { status: 400 }
      );
    }

    if (!isValidEmail(email)) {
      return NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      );
    }

    if (action === 'login') {
      let user: UserSession;

      if (email === DEMO_EMAIL && password === DEMO_PASSWORD) {
        user = {
          name: 'Admin',
          email: DEMO_EMAIL,
          org: 'SentinelMind HQ',
          role: 'Administrator',
        };
      } else if (email === DEMO_EMAIL && password !== DEMO_PASSWORD) {
        return NextResponse.json(
          { error: 'Invalid credentials' },
          { status: 401 }
        );
      } else {
        // Accept any valid email for non-demo users
        user = {
          name: email.split('@')[0],
          email,
          org: email.split('@')[1]?.split('.')[0] || 'Unknown',
          role: 'Analyst',
        };
      }

      return NextResponse.json({ success: true, user });
    }

    if (action === 'signup') {
      if (!name) {
        return NextResponse.json(
          { error: 'Name is required for signup' },
          { status: 400 }
        );
      }

      const user: UserSession = {
        name: name || email.split('@')[0],
        email,
        org: org || 'Unaffiliated',
        role: role || 'Analyst',
      };

      return NextResponse.json({ success: true, user });
    }

    return NextResponse.json(
      { error: 'Invalid action. Use "login" or "signup"' },
      { status: 400 }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Internal server error';
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
