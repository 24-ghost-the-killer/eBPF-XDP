import { NextRequest, NextResponse } from 'next/server'

// Server-side proxy to Prometheus. The appliance's Prometheus is bound to
// 127.0.0.1:9091 (private by design); this route forwards the browser's
// /api/prom/* requests to it, so Prometheus is never exposed to the client and
// there are no CORS issues. In dev, reach it with an SSH tunnel:
//   ssh -N -L 9091:127.0.0.1:9091 test_server@192.168.1.193
// Override the target with the PROM_URL env var.
export const dynamic = 'force-dynamic'

const PROM = process.env.PROM_URL || 'http://localhost:9091'

export async function GET(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  const path = params.path.join('/')
  const url = `${PROM}/${path}${req.nextUrl.search}`
  try {
    const r = await fetch(url, { cache: 'no-store' })
    const body = await r.text()
    return new NextResponse(body, {
      status: r.status,
      headers: {
        'content-type': r.headers.get('content-type') || 'application/json',
      },
    })
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    return NextResponse.json(
      { status: 'error', error: `proxy to ${PROM} failed: ${msg}` },
      { status: 502 }
    )
  }
}
