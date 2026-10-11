# xdp-sentinel dashboard

A Next.js (App Router) + TypeScript + Tailwind monitoring UI for the
xdp-sentinel appliance. It reads live data from the appliance's Prometheus and
shows status, live attack indicators, top talkers, blocking capacity, the ML
pipeline and infra health — the same data as the Grafana "DDoS Command Center",
in a custom app.

## How it reaches the data

The appliance's Prometheus is bound to `127.0.0.1:9091` (private by design). The
app never talks to it directly from the browser — a Next **server-side proxy**
(`app/api/prom/[...path]/route.ts`) forwards `/api/prom/*` to Prometheus. So the
browser stays same-origin (no CORS) and Prometheus is never exposed.

In development, give the Next server a path to Prometheus with an **SSH tunnel**:

```sh
ssh -N -L 9091:127.0.0.1:9091 test_server@192.168.1.193
```

That maps the appliance's Prometheus to `localhost:9091` on your machine, which
is the proxy's default target. Point it elsewhere with `PROM_URL=...`.

## Run

```sh
cd dashboard
npm install
# terminal 1: keep the tunnel open
ssh -N -L 9091:127.0.0.1:9091 test_server@192.168.1.193
# terminal 2:
npm run dev        # http://localhost:3000
```

Build / serve for production:

```sh
npm run build
PROM_URL=http://127.0.0.1:9091 npm start   # run ON the appliance (or behind a tunnel)
```

## Layout

- **Status** — dataplane up, posture (NORMAL / UNDER ATTACK), live drop / rate-limit / pass pps, max block capacity.
- **Live attack indicators** — traffic vs drops, TCP-flag mix (SYN-flood signature), protocol mix.
- **Top talkers** — top sending/receiving source IPs by live bit-rate.
- **Blocking capacity** — measured drop capacity and headroom.
- **ML pipeline & infra** — benign vs quarantined feature windows, switch status, NIC RX drops.

## Metrics used

All from Prometheus: `xs_verdict_packets_total`, `xs_rx_packets_total`,
`xs_tcp_flags_packets_total`, `xs_l4_packets_total`, `xs_policy_event_packets_total`,
`xs_talker_{tx,rx}_bytes_total`, `xs_capacity_*`, `xs_collector_*`, `ALERTS`,
`up{job=...}`, `gs1900_*`, `node_network_receive_drop_total`.
