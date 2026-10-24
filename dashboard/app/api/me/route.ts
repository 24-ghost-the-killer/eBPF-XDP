import { NextRequest, NextResponse } from 'next/server'
import { verifySession, sessionIsAdmin, PAGE_IDS } from '@/lib/authz'

// Who am I? Returns identity, group, allowed pages and admin flag so the UI can
// hide what the user cannot use. When auth is disabled on the server, reports
// authDisabled with all pages so the UI is unchanged.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const secret = process.env.DASH_SESSION
  const authOn = !!secret && (!!process.env.DASH_PASSWORD || !!process.env.DASH_USERS || !!process.env.DASH_USERS_FILE)
  if (!authOn) {
    return NextResponse.json({ authDisabled: true, pages: PAGE_IDS, isAdmin: true })
  }
  const s = await verifySession(secret!, req.cookies.get('dash_auth')?.value)
  if (!s) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  return NextResponse.json({ username: s.u, group: s.g, pages: s.p, isAdmin: sessionIsAdmin(s) })
}
