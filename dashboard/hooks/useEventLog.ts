'use client'
import { useEffect, useRef, useState } from 'react'
import { instant, scalar, type InstantResult } from '@/lib/prom'
import { bps } from '@/lib/format'

export type Cat = 'traffic' | 'security' | 'ai' | 'sys'
export interface LogEvent {
  id: number
  ts: Date
  tag: string
  cat: Cat
  msg: string
}

let _id = 0
const MAX = 1200

const n = (x: number) => (x >= 1000 ? (x / 1000).toFixed(1) + 'k' : String(Math.round(x)))
const byLabel = (r: InstantResult[], key: string) =>
  Object.fromEntries(r.map((s) => [s.metric[key] ?? '_', parseFloat(s.value[1])]))
const sum = (o: Record<string, number>) => Object.values(o).reduce((a, b) => a + b, 0)
const vlanName = (ifc: string) =>
  ifc === 'vlan10' ? 'VLAN10/wan' : ifc === 'vlan20' ? 'VLAN20/lan' : ifc

interface Snap {
  attack: boolean
  dropping: boolean
  ratelimiting: boolean
  extActive: boolean
  connFlood: boolean
  suspn: number
  tkip: string | null
  // risk engine + defenses
  threatState: number
  riskLevel: number
  autoActs: number
  mitRate: number
  flags: Record<string, number>
  layers: Record<string, number>
}

const THREAT = ['NORMAL', 'SUSPECT', 'UNDER ATTACK']

export function useEventLog(intervalMs = 3000) {
  const [events, setEvents] = useState<LogEvent[]>([])
  const prev = useRef<Snap | null>(null)
  const ticks = useRef(0)

  useEffect(() => {
    let alive = true
    const push = (tag: string, cat: Cat, msg: string) =>
      setEvents((e) => [...e.slice(-(MAX - 1)), { id: ++_id, ts: new Date(), tag, cat, msg }])

    push('SYS', 'sys', 'xdp-sentinel monitor initialising — connecting to prometheus…')

    const tick = async () => {
      ticks.current++
      const quiet = ticks.current % 5 === 1 // low-activity categories ~every 15s
      try {
        const [
          rxI, passI, dropI, rxBpsI, nicRxI, nicTxI,
          flagsI, l4I, l3I, vlanI, extI, fragI,
          anomI, malI, connI, rlI, rtrackI,
          postureI, alertsI, suspectI, tkI,
        ] = await Promise.all([
          instant('sum by(iface)(rate(xs_rx_packets_total[1m]))'),
          instant('sum by(iface)(rate(xs_verdict_packets_total{verdict="pass"}[1m]))'),
          instant('sum by(iface)(rate(xs_verdict_packets_total{verdict="drop"}[1m]))'),
          instant('sum(rate(xs_rx_bytes_total[1m]))*8'),
          instant('rate(node_network_receive_packets_total{device="enp1s0"}[1m])'),
          instant('rate(node_network_transmit_packets_total{device="enp1s0"}[1m])'),
          instant('sum by(class)(rate(xs_tcp_flags_packets_total[1m]))'),
          instant('sum by(proto)(rate(xs_l4_packets_total[1m]))'),
          instant('sum by(proto)(rate(xs_l3_packets_total[1m]))'),
          instant('sum by(tags)(rate(xs_vlan_packets_total[1m]))'),
          instant('sum(rate(xs_ipv6_ext_packets_total[1m]))'),
          instant('sum by(kind)(rate(xs_fragment_packets_total[1m]))'),
          instant('sum(rate(xs_anomaly_packets_total[1m]))'),
          instant('sum(rate(xs_parse_outcome_packets_total{class="malformed"}[1m]))'),
          instant('sum(rate(xs_conntrack_packets_total[1m]))'),
          instant('sum(rate(xs_policy_event_packets_total{event="rate_limited"}[1m]))'),
          instant('sum(rate(xs_rate_tracked_packets_total[1m]))'),
          instant('count(ALERTS{alertstate="firing",severity=~"warning|critical"}) or vector(0)'),
          instant('ALERTS{alertstate="firing"}'),
          instant('xs_collector_suspect_windows_total'),
          instant('topk(1, rate(xs_talker_tx_bytes_total[5m])*8)'),
        ])
        if (!alive) return

        const rx = byLabel(rxI, 'iface')
        const pass = byLabel(passI, 'iface')
        const drop = byLabel(dropI, 'iface')
        const flag = byLabel(flagsI, 'class')
        const l4 = byLabel(l4I, 'proto')
        const l3 = byLabel(l3I, 'proto')
        const vlan = byLabel(vlanI, 'tags')
        const frag = byLabel(fragI, 'kind')
        const rxBps = scalar(rxBpsI, 0)!
        const nicRx = scalar(nicRxI, 0)!
        const nicTx = scalar(nicTxI, 0)!
        const ext = scalar(extI, 0)!
        const anom = scalar(anomI, 0)!
        const mal = scalar(malI, 0)!
        const conn = scalar(connI, 0)!
        const rl = scalar(rlI, 0)!
        const rtrack = scalar(rtrackI, 0)!
        const attack = scalar(postureI, 0)! > 0
        const suspn = scalar(suspectI, 0)!
        const xdpSeen = sum(rx)
        const totalDrop = sum(drop)
        const first = prev.current == null
        if (first) push('SYS', 'sys', 'connected ✓ — streaming full dataplane telemetry')

        // ---------- TRAFFIC (per-tick) ----------
        for (const ifc of Object.keys(rx).sort())
          push('IN', 'traffic', `${vlanName(ifc)} in=${n(rx[ifc])} pass=${n(pass[ifc] || 0)} drop=${n(drop[ifc] || 0)} p/s`)
        push('OUT', 'traffic', `egress (enp1s0) out=${n(nicTx)} p/s`)
        push('NIC', 'traffic', `NIC-received=${n(nicRx)} p/s · XDP-seen=${n(xdpSeen)} p/s · delta=${n(nicRx - xdpSeen)} p/s`)
        push('BW', 'traffic', `ingress bandwidth ${bps(rxBps)}`)
        push('VLAN', 'traffic', `tags: untagged=${n(vlan['0'] || 0)} 1-tag=${n(vlan['1'] || 0)} 2-tag/QinQ=${n(vlan['2'] || 0)} p/s`)

        // ---------- SECURITY / TCP (per-tick) ----------
        push('SYN', 'security', `SYN=${n(flag.syn || 0)} SYN-ACK=${n(flag.synack || 0)} ACK=${n(flag.ack || 0)} FIN=${n(flag.fin || 0)} RST=${n(flag.rst || 0)} p/s`)
        push('CONN', 'security', `untracked TCP ${n(conn)} p/s (ACK/RST-flood gauge)`)

        // ---------- quiet categories (~every 15s so they appear even at 0) ----------
        if (quiet) {
          push('DROP', 'security', `dropped total ${n(totalDrop)} p/s`)
          push('EXT', 'traffic', `IPv6 extension-header pkts ${n(ext)} p/s`)
          push('FRAG', 'traffic', `fragments first=${n(frag.first || 0)} later=${n(frag.later || 0)} p/s`)
          push('ICMP', 'traffic', `icmp=${n(l4.icmp || 0)} icmpv6=${n(l4.icmpv6 || 0)} p/s`)
          push('ANOM', 'security', `anomalies ${n(anom)} p/s · malformed ${n(mal)} p/s`)
          push('RATE', 'security', `rate-tracked sources ${n(rtrack)} p/s · limited ${n(rl)} p/s`)
          push('L3', 'traffic', `ipv4=${n(l3.ipv4 || 0)} ipv6=${n(l3.ipv6 || 0)} arp=${n(l3.arp || 0)} p/s`)
        }

        // ---------- threshold events ----------
        if (totalDrop > 0.5)
          for (const ifc of Object.keys(drop))
            if (drop[ifc] > 0.5) push('DROP', 'security', `dropping ${n(drop[ifc])} p/s on ${vlanName(ifc)}`)
        if (ext > 0.5 && (first || !prev.current?.extActive)) push('EXT', 'traffic', `IPv6 extension headers now present (${n(ext)} p/s) — watching for ext-chain evasion`)
        if ((frag.later || 0) > 1) push('FRAG', 'security', `non-first fragments ${n(frag.later)} p/s — possible fragment flood`)
        if (mal > 0.5) push('MALF', 'security', `${n(mal)} p/s malformed frames rejected by parser`)
        if (anom > 0.5) push('ANOM', 'security', `${n(anom)} p/s anomalous (bad flags / LAND / udp-len)`)

        // ---------- AI / INTELLIGENCE (risk engine + auto-mitigate transitions) ----------
        const dropping = totalDrop > 1
        const ratelimiting = rl > 1
        const connFlood = conn > 5
        const syn = flag.syn || 0
        const synack = flag.synack || 1
        if (attack && (first || !prev.current?.attack)) {
          const names = Array.from(new Set(alertsI.map((s) => s.metric.alertname))).join(', ')
          push('AI', 'ai', `⚠ THREAT DETECTED — ${names || 'attack signature'} → raising risk level`)
        }
        if (!attack && prev.current?.attack) push('AI', 'ai', 'threat cleared — risk level normal')
        if (dropping && (first || !prev.current?.dropping)) push('AI', 'ai', `MITIGATION ENGAGED — drop flags active, dropping ${n(totalDrop)} p/s`)
        if (!dropping && prev.current?.dropping) push('AI', 'ai', 'mitigation lifted — observe-only baseline restored')
        if (ratelimiting && (first || !prev.current?.ratelimiting)) push('AI', 'ai', `rate-limiter ACTIVATED — capping abusive sources (${n(rl)} p/s)`)
        if (!ratelimiting && prev.current?.ratelimiting) push('AI', 'ai', 'rate-limiter stood down')
        if (syn > 150 && syn > 4 * synack) push('AI', 'ai', `SYN-flood pattern (syn:synack ${(syn / synack).toFixed(0)}:1, ${n(syn)} p/s) — recommend DROP_SYN`)
        if ((l4.udp || 0) > 1000) push('AI', 'ai', `UDP flood watch — ${n(l4.udp || 0)} p/s, evaluating DROP_UDP`)
        if (connFlood && (first || !prev.current?.connFlood)) push('AI', 'ai', `ACK/RST flood suspected — ${n(conn)} p/s untracked TCP, conntrack guarding`)
        if (prev.current && suspn > prev.current.suspn) push('AI', 'ai', `anomalous traffic window detected & quarantined (suspect total ${suspn})`)

        // ---------- top talker ----------
        const tk = tkI[0]
          ? { ip: tkI[0].metric.ip, scope: tkI[0].metric.scope, v: parseFloat(tkI[0].value[1]) }
          : null
        if (tk && (first || prev.current?.tkip !== tk.ip)) push('NET', 'traffic', `top talker: ${tk.ip} (${tk.scope}) ${bps(tk.v)}`)

        // ---------- AI RISK ENGINE + ACTIVE DEFENSES ----------
        const [threatI, riskLvlI, zI, ddosI, ifI, actsI, mitRateI, topClassI, cfgFlagI, layerI, trackI] =
          await Promise.all([
            instant('max(xs_threat_state)'),
            instant('max(xs_risk_level)'),
            instant('max(xs_anomaly_score01)'),
            instant('max(xs_ddos_score)'),
            instant('max(xs_anomaly_iforest)'),
            instant('sum(xs_auto_actions_total)'),
            instant('max(xs_mitigation_rate_pps)'),
            instant('topk(1, max by(class)(xs_ddos_class_probability{class!="benign"}))'),
            instant('xs_config_flag'),
            instant('max by(layer)(xs_layer_state)'),
            instant('xs_talker_tracked_ips'),
          ])
        if (!alive) return

        const threatState = Math.round(scalar(threatI, 0)!)
        const riskLevel = Math.round(scalar(riskLvlI, 0)!)
        const zscore = scalar(zI, 0)!
        const ddosScore = scalar(ddosI, 0)!
        const iforest = scalar(ifI)
        const autoActs = Math.round(scalar(actsI, 0)!)
        const mitRate = scalar(mitRateI, 0)!
        const trackedIps = Math.round(scalar(trackI, 0)!)
        const flagMap: Record<string, number> = {}
        for (const sx of cfgFlagI) flagMap[`${sx.metric.iface}/${sx.metric.flag}`] = parseFloat(sx.value[1])
        const layerMap: Record<string, number> = {}
        for (const sx of layerI) layerMap[sx.metric.layer] = parseFloat(sx.value[1])
        const topClass = topClassI[0]
          ? { label: topClassI[0].metric.class, v: parseFloat(topClassI[0].value[1]) }
          : null
        const p = prev.current

        // periodic snapshot of the engine (~every 15s, so it shows even at rest)
        if (quiet) {
          push('RISK', 'ai', `engine: state=${THREAT[threatState]} level=${riskLevel} z=${zscore.toFixed(2)} iforest=${iforest == null ? 'n/a' : iforest.toFixed(2)} ddos=${ddosScore.toFixed(2)}`)
          push('TRACK', 'traffic', `${trackedIps} source IPs tracked · ${autoActs} auto-actions lifetime`)
        }
        // transitions
        if (p) {
          if (threatState !== p.threatState) push('AI', 'ai', `threat state ${THREAT[p.threatState] ?? p.threatState} → ${THREAT[threatState] ?? threatState}`)
          if (riskLevel !== p.riskLevel) push('AI', 'ai', `mitigation ladder level ${p.riskLevel} → ${riskLevel}`)
          if (autoActs > p.autoActs) push('ACTION', 'ai', `auto-mitigation change applied (lifetime ${autoActs})`)
          if (Math.abs(mitRate - p.mitRate) > 0.5) push('RATE', 'security', `per-source cap now ${n(mitRate)} p/s`)
          for (const k in flagMap)
            if (p.flags[k] !== undefined && flagMap[k] !== p.flags[k]) {
              const [ifc, flag] = k.split('/')
              push('FLAG', 'security', `${flag} ${flagMap[k] > 0 ? 'ARMED' : 'DISARMED'} on ${vlanName(ifc)}`)
            }
          for (const ly in layerMap)
            if (p.layers[ly] !== undefined && layerMap[ly] !== p.layers[ly])
              push('LAYER', 'security', `${ly.toUpperCase()} layer → ${layerMap[ly] >= 2 ? 'ATTACK' : layerMap[ly] >= 1 ? 'SUSPECT' : 'clear'}`)
        }
        // detector spikes
        if (topClass && topClass.v > 0.5) push('DETECT', 'ai', `classifier flags ${topClass.label} (p=${topClass.v.toFixed(2)})`)
        if (iforest != null && iforest > 0.6) push('SCORE', 'ai', `isolation-forest score ${iforest.toFixed(2)} — elevated`)
        if (zscore > 0.6) push('SCORE', 'ai', `statistical z-score ${zscore.toFixed(2)} — elevated`)

        prev.current = {
          attack, dropping, ratelimiting, extActive: ext > 0.5, connFlood, suspn, tkip: tk?.ip ?? null,
          threatState, riskLevel, autoActs, mitRate, flags: flagMap, layers: layerMap,
        }
      } catch (e) {
        push('ERR', 'sys', `prometheus unreachable: ${e instanceof Error ? e.message : String(e)}`)
        prev.current = null
      }
    }

    tick()
    const id = setInterval(tick, intervalMs)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [intervalMs])

  return events
}
