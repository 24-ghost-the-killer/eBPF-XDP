import { NextRequest, NextResponse } from 'next/server'
import { requirePerm } from '@/lib/api-auth'
import { audit } from '@/lib/audit'
import { SCENARIOS, SCENARIO_IDS, MIN_S, MAX_S, readStatus, readHistory, readRequest, writeRequest } from '@/lib/sim'

// Attack simulator.
//   GET  /api/simulate                       -> { status, scenarios, current, history, pending }
//   POST /api/simulate { scenario, duration } -> start one (needs simulator.run)
//   POST /api/simulate { stop: true }         -> stop the running one
// The work is done by the root helper xs-simulate (see lib/sim.ts).
export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'simulator')
  if (auth.error) return auth.error
  const current = readStatus()
  const request = readRequest()
  // a start request the helper has not picked up yet (or the helper is not installed)
  const pending = request?.action === 'start' && request.id !== current?.id
    ? { id: request.id, at: request.at, waitedSec: Math.max(0, Date.now() / 1000 - (request.at ?? 0)) } : null
  return NextResponse.json({
    status: 'success', scenarios: SCENARIOS, limits: { min: MIN_S, max: MAX_S },
    current, pending, history: [...readHistory()].reverse().slice(0, req.nextUrl.searchParams.get('all') === '1' ? 200 : 20),
  })
}

export async function POST(req: NextRequest) {
  const auth = await requirePerm(req, 'simulator.run')
  if (auth.error) return auth.error
  const body = await req.json().catch(() => null)
  const by = auth.access.authDisabled ? '' : auth.access.username
  const cur = readStatus()

  if (body?.stop) {
    if (!cur || cur.state !== 'running') return NextResponse.json({ status: 'error', error: 'No simulation is running.' }, { status: 409 })
    writeRequest({ action: 'stop', id: cur.id, by })
    audit(req, { user: by, kind: auth.access.kind, category: 'simulator', action: 'simulator.stop', target: cur.scenario, summary: `Stopped the ${cur.label} simulation` })
    return NextResponse.json({ status: 'success' })
  }

  const scenario = String(body?.scenario ?? '')
  if (!SCENARIO_IDS.includes(scenario)) return NextResponse.json({ status: 'error', error: 'Pick an attack type.' }, { status: 400 })
  const duration = Math.max(MIN_S, Math.min(MAX_S, Math.round(Number(body?.duration) || 20)))
  if (cur?.state === 'running' && Date.now() / 1000 - cur.started_at < MAX_S + 120) {
    return NextResponse.json({ status: 'error', error: `A simulation (${cur.label}) is already running.` }, { status: 409 })
  }
  const player = typeof body?.player === 'string' ? body.player.replace(/[^\p{L}\p{N} ._-]/gu, '').trim().slice(0, 24) : ''
  const game = body?.game === true && !!player
  const id = writeRequest({ action: 'start', scenario, duration, by, ...(game ? { player, game } : {}) })
  const label = SCENARIOS.find((s) => s.id === scenario)!.label
  audit(req, {
    user: by, kind: auth.access.kind, category: 'simulator', action: 'simulator.start', target: scenario,
    summary: game ? `Red vs blue: ${player} attacks with ${label} (${duration} s)` : `Started a ${duration} s ${label} simulation`, detail: { scenario, duration, id, player: game ? player : undefined },
  })
  return NextResponse.json({ status: 'success', id })
}
