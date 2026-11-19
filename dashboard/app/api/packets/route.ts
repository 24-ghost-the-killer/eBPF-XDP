import { NextRequest, NextResponse } from 'next/server'
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'

// Live packet capture for the packet explainer (root helper xs-capture).
//   POST /api/packets { count, filter }  -> { id }     (needs packets.capture)
//   GET  /api/packets?id=<id>            -> the pcap file, or 202 while it is recorded
export const dynamic = 'force-dynamic'

const FILTERS = ['all', 'tcp', 'udp', 'icmp', 'arp', 'dns']
const dataDir = () => dirname(process.env.DASH_USERS_FILE || '/home/test_server/xdp-sentinel-data/dash-users.json')

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'packets.capture')
  if (auth.error) return auth.error
  const b = await req.json().catch(() => null)
  const count = Math.max(1, Math.min(50, Math.round(Number(b?.count) || 30)))
  const filter = FILTERS.includes(b?.filter) ? b.filter : 'all'
  const id = randomUUID()
  const by = auth.access.authDisabled ? '' : auth.access.username
  const f = join(dataDir(), 'capture.json')
  mkdirSync(dataDir(), { recursive: true })
  writeFileSync(`${f}.tmp`, JSON.stringify({ id, count, filter, by, at: Date.now() }), { mode: 0o644 })
  renameSync(`${f}.tmp`, f)
  audit(req, { user: by, kind: auth.access.kind, category: 'packets', action: 'packets.capture', target: id, summary: `Captured up to ${count} packet headers (${filter})` })
  return NextResponse.json({ status: 'success', id })
}

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'packets.capture')
  if (auth.error) return auth.error
  const id = req.nextUrl.searchParams.get('id') || ''
  if (!/^[0-9a-f-]{36}$/.test(id)) return NextResponse.json({ status: 'error', error: 'bad id' }, { status: 400 })
  const f = join(dataDir(), `capture-${id}.pcap`)
  if (!existsSync(f)) return NextResponse.json({ status: 'pending' }, { status: 202 })
  return new NextResponse(readFileSync(f), { headers: { 'content-type': 'application/vnd.tcpdump.pcap', 'cache-control': 'no-store' } })
}
