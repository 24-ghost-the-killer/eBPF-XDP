import { NextRequest, NextResponse } from 'next/server'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import { requirePerm } from '@/lib/api-auth'

// Dataplane health: which XDP program every interface really runs, whether it
// is older than the object installed on disk (a rebuilt dataplane is NOT picked
// up until `sentinelctl attach --replace`), whether the agent runs the binary
// on disk, and whether Prometheus is getting its metrics.
//
// Sources, all read-only and none needing root:
//   * `ip -j -d link`            program id + XDP mode per interface
//   * agent /api/dataplane.json  program load times (agent runs as root; newer agents only)
//   * the object and agent binary on disk (mtime, sha256)
//   * `systemctl show`           when the agent service started
//   * Prometheus                 xs_agent_up / xs_dataplane_attached freshness
export const dynamic = 'force-dynamic'

const run = promisify(execFile)
const PROM = process.env.PROM_URL || 'http://localhost:9091'
const AGENT = process.env.AGENT_URL || 'http://localhost:9464'
const OBJ = process.env.DASH_BPF_OBJ || '/usr/lib/xdp-sentinel/xdp_main.bpf.o'
const AGENT_BIN = process.env.DASH_AGENT_BIN || '/usr/local/bin/sentinel-agent'
const STATE_DIR = process.env.DASH_SENTINEL_STATE || '/var/lib/xdp-sentinel'
const PATH = '/usr/sbin:/usr/bin:/sbin:/bin'

type Tone = 'good' | 'warn' | 'bad' | 'neutral'
interface Check { id: string; tone: Tone; title: string; text: string; fix?: string }

async function sh(cmd: string, args: string[]) {
  try {
    const { stdout } = await run(cmd, args, { timeout: 5000, env: { ...process.env, PATH }, maxBuffer: 4 << 20, encoding: 'utf8' })
    return stdout
  } catch {
    return null
  }
}
async function json<T>(url: string): Promise<T | null> {
  try {
    const r = await fetch(url, { cache: 'no-store', signal: AbortSignal.timeout(4000) })
    return r.ok ? ((await r.json()) as T) : null
  } catch {
    return null
  }
}
async function fileInfo(path: string, hash: boolean) {
  try {
    const st = await stat(path)
    const sha = hash ? createHash('sha256').update(await readFile(path)).digest('hex') : undefined
    return { path, mtime: st.mtimeMs, size: st.size, sha }
  } catch {
    return { path, mtime: null as number | null, size: null as number | null, sha: undefined }
  }
}
async function prom(expr: string) {
  const j = await json<{ status: string; data: { result: { metric: Record<string, string>; value: [number, string] }[] } }>(`${PROM}/api/v1/query?query=${encodeURIComponent(expr)}`)
  return j?.status === 'success' ? j.data.result : null
}

interface IpLink { ifname: string; operstate?: string; master?: string; xdp?: { mode?: number; prog?: { id?: number } } }
interface AgentIface { iface: string; prog_id: number; mode: string; prog_name: string; tag: string; loaded_at: number; configured: boolean; pinned_prog_id: number | null }
interface AgentDp { now: number; agent: { version: string; pid: number }; object: { path: string; mtime: number | null }; configured: string[]; interfaces: AgentIface[] }

const MODE = ['none', 'native', 'generic', 'offload']

const tsOf = (s: string | null) => {
  const m = s && /ActiveEnterTimestamp=(.+)/.exec(s)
  const t = m ? Date.parse(m[1].replace(/ ([A-Z]{2,5})$/, '')) : NaN
  return Number.isFinite(t) ? t : null
}

export async function GET(req: NextRequest) {
  const auth = await requirePerm(req, 'health')
  if (auth.error) return auth.error

  const [ipOut, dp, obj, bin, sys, healthz, readyz, state, up, attached, twingate] = await Promise.all([
    sh('ip', ['-j', '-d', 'link', 'show']),
    json<AgentDp>(`${AGENT}/api/dataplane.json`),
    fileInfo(OBJ, true),
    fileInfo(AGENT_BIN, false),
    sh('systemctl', ['show', 'sentinel-agent', '-p', 'ActiveState,SubState,ActiveEnterTimestamp,MainPID,NRestarts']),
    fetch(`${AGENT}/healthz`, { cache: 'no-store', signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false),
    fetch(`${AGENT}/readyz`, { cache: 'no-store', signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false),
    json<{ mode?: string; flags?: string[]; schema_hash?: string; iface?: string }>(`${AGENT}/api/state.json`),
    prom('time() - timestamp(xs_agent_up)'),
    prom('xs_dataplane_attached'),
    readFile(`${STATE_DIR}/twingate.applied.json`, 'utf8').then((s) => JSON.parse(s) as { veth?: string }).catch(() => null),
  ])

  // ---- interfaces with an XDP program ----
  let links: IpLink[] = []
  try { links = JSON.parse(ipOut ?? '[]') } catch {}
  const fromAgent = new Map((dp?.interfaces ?? []).map((i) => [i.iface, i]))
  const configured = new Set(dp?.configured ?? (attached ?? []).map((r) => r.metric.iface))
  const role = (name: string) =>
    name === 'vlan10' ? 'WAN side (VLAN10)' : name === 'vlan20' ? 'LAN side (VLAN20)' : name === twingate?.veth ? 'Twingate connector' : configured.has(name) ? 'monitored' : 'other'
  const ifaces = links
    .filter((l) => l.xdp?.prog?.id || configured.has(l.ifname))
    .map((l) => {
      const a = fromAgent.get(l.ifname)
      const id = l.xdp?.prog?.id ?? a?.prog_id ?? 0
      return {
        iface: l.ifname, role: role(l.ifname), master: l.master ?? null, up: l.operstate === 'UP',
        progId: id, mode: a?.mode ?? MODE[l.xdp?.mode ?? 0] ?? 'unknown', configured: configured.has(l.ifname),
        progName: a?.prog_name ?? null, tag: a?.tag ?? null, loadedAt: a?.loaded_at ? a.loaded_at * 1000 : null,
        pinnedId: a?.pinned_prog_id ?? null,
      }
    })

  // ---- checks ----
  const checks: Check[] = []
  const svc = sys ?? ''
  const active = /ActiveState=active/.test(svc)
  const started = tsOf(svc)
  checks.push(active && healthz
    ? { id: 'agent', tone: 'good', title: 'Agent is running', text: `sentinel-agent is active${started ? ` since ${new Date(started).toLocaleString('en-GB')}` : ''}${readyz ? ' and ready' : ', but not ready yet'}.` }
    : { id: 'agent', tone: 'bad', title: 'Agent is not running', text: 'Without it there is no detection, no auto-mitigation and no metrics.', fix: 'sudo systemctl restart sentinel-agent' })
  if (active && started && bin.mtime && bin.mtime > started + 5000) {
    checks.push({ id: 'agent-bin', tone: 'warn', title: 'A newer agent is installed but not running', text: `The binary on disk is from ${new Date(bin.mtime).toLocaleString('en-GB')}, after the running agent started. Restart it to pick it up.`, fix: 'sudo systemctl restart sentinel-agent' })
  }
  if (!obj.mtime) checks.push({ id: 'object', tone: 'bad', title: 'Dataplane object missing', text: `${OBJ} is not on disk.` })

  // stale programs: loaded before the object on disk was installed (exact, with the
  // agent's load times) or, on an older agent, an id older than every monitored one
  const confIds = ifaces.filter((i) => i.configured && i.progId).map((i) => i.progId)
  const minConf = confIds.length ? Math.min(...confIds) : 0
  for (const i of ifaces) {
    const fix = i.role === 'Twingate connector'
      // the attach script reuses whatever is already on the veth and needs its env file
      // (container name), so: drop the old program, then let it attach the current one
      ? `sudo sh -c '/usr/local/bin/sentinelctl detach -i ${i.iface} && set -a && . /etc/xdp-sentinel/twingate.env && set +a && /usr/local/bin/xs-twingate-attach'`
      : `sudo sentinelctl attach -i ${i.iface} --mode ${i.mode === 'native' ? 'native' : 'generic'} --replace`
    if (!i.progId) {
      checks.push({ id: `if-${i.iface}`, tone: 'bad', title: `${i.iface}: no firewall attached`, text: `${i.role}: traffic here is not inspected or filtered at all.`, fix })
      continue
    }
    let stale: boolean | null = null
    if (i.loadedAt && obj.mtime) stale = i.loadedAt + 5000 < obj.mtime
    else if (!i.configured && minConf && i.progId < minConf) stale = true
    if (stale) {
      checks.push({
        id: `if-${i.iface}`, tone: 'bad', title: `${i.iface}: running an old firewall program`,
        text: `${i.role}: program #${i.progId} was loaded ${i.loadedAt ? new Date(i.loadedAt).toLocaleString('en-GB') : 'before the programs on vlan10/vlan20'}, so it predates the dataplane installed ${obj.mtime ? new Date(obj.mtime).toLocaleString('en-GB') : 'now'}. Fixes since then (e.g. the ARP rate limit) don’t apply to traffic here.`,
        fix,
      })
    } else if (i.configured && i.pinnedId && i.pinnedId !== i.progId) {
      checks.push({ id: `if-${i.iface}`, tone: 'warn', title: `${i.iface}: attached program isn’t the agent’s`, text: `The interface runs #${i.progId} but the agent manages #${i.pinnedId}; its counters and controls may not match.`, fix })
    } else {
      checks.push({ id: `if-${i.iface}`, tone: 'good', title: `${i.iface}: current program`, text: `${i.role}: program #${i.progId} in ${i.mode} mode${stale === null ? ' (load time unknown: needs the newer agent)' : ''}.` })
    }
  }
  if (ifaces.some((i) => i.mode === 'generic')) {
    checks.push({ id: 'mode', tone: 'neutral', title: 'Generic (SKB) mode', text: 'The NIC driver has no native XDP, so the program runs after the kernel builds its packet buffers: correct, but it costs more CPU per packet than native mode.' })
  }
  const age = up?.[0] ? parseFloat(up[0].value[1]) : null
  checks.push(age !== null && age < 60
    ? { id: 'prom', tone: 'good', title: 'Prometheus is collecting', text: `Last sample ${Math.max(0, Math.round(age))} s ago.` }
    : { id: 'prom', tone: up === null ? 'bad' : 'warn', title: up === null ? 'Prometheus unreachable' : 'Metrics are stale', text: up === null ? 'The dashboard can’t reach Prometheus, so charts and attack history stop updating.' : `The newest agent sample is ${age === null ? 'missing' : `${Math.round(age)} s old`}.`, fix: 'sudo systemctl restart prometheus' })
  if (!dp) {
    checks.push({ id: 'agent-api', tone: 'neutral', title: 'Program load times unavailable', text: 'The running agent predates /api/dataplane.json, so “stale” is judged from program ids. Deploying the staged agent gives exact load times.' })
  }

  const order: Record<Tone, number> = { bad: 0, warn: 1, neutral: 3, good: 2 }
  checks.sort((x, y) => order[x.tone] - order[y.tone])
  return NextResponse.json({
    status: 'success', at: Date.now(),
    overall: checks.some((c) => c.tone === 'bad') ? 'bad' : checks.some((c) => c.tone === 'warn') ? 'warn' : 'good',
    checks, interfaces: ifaces,
    object: { ...obj, sha: obj.sha?.slice(0, 16) },
    agent: { active, started, binary: bin, version: dp?.agent.version ?? null, pid: dp?.agent.pid ?? null, mode: state?.mode ?? null, flags: state?.flags ?? [], schema: state?.schema_hash?.slice(0, 16) ?? null, restarts: Number(/NRestarts=(\d+)/.exec(svc)?.[1] ?? 0) },
  })
}
