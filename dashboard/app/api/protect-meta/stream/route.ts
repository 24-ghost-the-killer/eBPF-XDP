import { NextRequest, NextResponse } from 'next/server'
import { protectActor } from '@/lib/api-auth'
import { subscribe, allPresence } from '@/lib/protect'

// Server-Sent Events: pushes every notes change (nickname, documentation, log)
// and editing-presence change to open Protection pages, so two people see each
// other's edits live. The client reloads everything on (re)connect, so an
// event missed while disconnected is never lost.
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  if ((await protectActor(req)) === null) return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  const enc = new TextEncoder()
  let cleanup = () => {}
  const stream = new ReadableStream({
    start(ctrl) {
      const send = (event: string, data: unknown) => {
        try { ctrl.enqueue(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)) } catch { cleanup() }
      }
      send('hello', { presence: allPresence() })
      const off = subscribe((e) => send(e.event, e.data))
      // Comment heartbeat keeps proxies and the browser from timing the stream out.
      const hb = setInterval(() => { try { ctrl.enqueue(enc.encode(': ping\n\n')) } catch { cleanup() } }, 15_000)
      cleanup = () => { off(); clearInterval(hb); try { ctrl.close() } catch {} }
      req.signal.addEventListener('abort', () => cleanup())
    },
    cancel() { cleanup() },
  })
  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    },
  })
}
