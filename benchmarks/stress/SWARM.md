# Swarm — distributed stress tester ("bots")

A controller + agent ("bot") setup to load-test **your own** xdp-sentinel target
from several machines at once, overcoming the single-machine / Wi-Fi pps ceiling.

> **Authorized testing only.** Only aim this at hosts you own or have written
> permission to test. A synchronized flood from many bots looks exactly like a
> DDoS to the target's network. The agents refuse non-private targets unless you
> pass `--allow-public`. This is a lab tool — it does not self-propagate, spoof
> source addresses, or hide itself.

## How it works

```
   your Mac                    your other computers
  ┌───────────┐   TCP 9000    ┌─────────┐ ┌─────────┐ ┌─────────┐
  │ controller │◀────────────▶│  bot 1  │ │  bot 2  │ │  bot 3  │
  └───────────┘  orders +     └────┬────┘ └────┬────┘ └────┬────┘
      you type   results            │ synchronized flood   │
      commands                      ▼          ▼           ▼
                              ┌──────────────────────────────┐
                              │   target (10.55.12.50, wlo1)  │
                              └──────────────────────────────┘
```

Each bot runs the local `flood.py` engine; the controller sends a synchronized
start time so every bot hits at the same instant, then aggregates their reports.

## Run it

**1. On your Mac (the controller):**
```sh
cd benchmarks/stress
python3 swarm_control.py            # listens on 0.0.0.0:9000
```

**2. On each other computer (a bot)** — copy `flood.py` + `swarm_agent.py` there:
```sh
python3 swarm_agent.py <mac-ip>:9000 --name box1
```
They connect back; the controller prints `[+] agent joined`.

**3. From the controller prompt:**
```
> list
> attack 10.55.12.50 --super -d 20            # every bot, max-volume UDP
> attack 10.55.12.50 --vector udp --ports 53,123 -d 15
> hammer 10.55.12.50 -d 30                     # multi-vector across bots
```

The controller prints the aggregate pps / Gbit/s across all bots.

## Watch the defence react

On the target, in another terminal:
```sh
sudo xdp stats -i wlo1 --interval 1
```
or open the advanced Grafana dashboard — the **Detection & Intelligence** and
**Multi-layer detection** rows light up, and (with auto-mitigation on) you'll see
the AI enable `drop_udp` / tighten the rate limiter and the drops climb.

## Notes
- Bots behind NAT are fine — they dial *out* to the controller.
- To flood from your Mac too, run an agent on it pointing at `127.0.0.1:9000`.
- Real reach still depends on each bot's link (Wi-Fi ≈ 90k pps/bot). Ten wired
  bots ≈ millions of pps aggregate. For single-host line rate use pktgen/TRex.
