import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'

// Server-side proxy to the sentinel-agent's read-only HTTP API, bound to
// 127.0.0.1:9464 on the appliance (private by design, like Prometheus). This
// route forwards /api/agent/* to it so the browser stays same-origin and the
// agent is never exposed to the client. Only GET is proxied -- the agent API
// is read-only, and the dashboard deliberately holds no write path.
// In dev, reach it with an SSH tunnel:
//   ssh -N -L 9464:127.0.0.1:9464 test_server@192.168.1.193
// Override the target with the AGENT_URL env var.
export const dynamic = 'force-dynamic'

const AGENT = process.env.AGENT_URL || 'http://localhost:9464'

export async function GET(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  const auth = await requirePerm(req, 'protect') // live: disabled accounts lose access at once
  if (auth.error) return auth.error
  if (!['api/services.json', 'api/state.json'].includes(params.path.join('/'))) {
    return NextResponse.json({ status: 'error', error: 'not allowed' }, { status: 404 })
  }
  const path = params.path.join('/')
  const url = `${AGENT}/${path}${req.nextUrl.search}`
  try {
    const r = await fetch(url, { cache: 'no-store', signal: AbortSignal.timeout(12000) })
    const body = await r.text()
    return new NextResponse(body, {
      status: r.status,
      headers: { 'content-type': r.headers.get('content-type') || 'application/json' },
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return NextResponse.json(
      { status: 'error', error: `proxy to ${AGENT} failed: ${msg}` },
      { status: 502 }
    )
  }
}
