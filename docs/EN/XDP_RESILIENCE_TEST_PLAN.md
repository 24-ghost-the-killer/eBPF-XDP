<!-- Language: **English** · [Dansk](../DK/XDP_RESILIENCE_TEST_PLAN.md) -->

# XDP Firewall Resilience Testing — Comprehensive Penetration Plan

**Target:** 192.168.1.193  
**Test Framework:** xdp-sentinel (integrated in /pentest/xdp_pentest.py)  
**Methodology:** Lab-only authorized network-layer resilience testing  
**Date:** 2026-10-23

---

## Executive Summary

This document outlines the **aggressive network-layer resilience testing** of a custom eBPF/XDP firewall/DDoS mitigation system. The test suite focuses on:

1. **XDP Parsing Bypass Attempts** — malformed headers, extreme fragmentation, non-standard protocol fields
2. **XDP Map Exhaustion** — high-volume stateless traffic to stress tracking structures  
3. **Kernel Drop Metrics** — collection and analysis of XDP_DROP verdicts and systemic bypasses

---

## Test Categories & Attack Vectors

### A. Layer 3 (IP) Bypass Vectors

#### 1. Malformed IP Headers
- **Malformed IHL** (Header Length): IHL=1-4 (should be ≥5)
  - Tests if XDP parser validates header structure strictly
  - Bypasses: Allows truncated headers → incomplete parsing
  - Expected: DROP / MALFORMED classification
  
- **Zero-Length Payload**: IP Total Length = 20 (header only, no L4)
  - Tests edge-case packet handling
  - Bypasses: May bypass L4 state tracking (no connection to establish)
  - Expected: DROP / MALFORMED or PASS (depending on design)
  
- **Negative Payload Length**: Crafted packets with impossible sizes
  - Tests integer overflow guards
  - Bypasses: Triggers negative buffer access → kernel crash (untested)
  - Expected: DROP / error handling

#### 2. IP Fragmentation Stress
- **Extreme Fragment Flood**: 8-byte fragments with MF (More Fragments) flag
  - Forces massive reassembly buffer allocation
  - Tests: XDP map capacity (vs_victim / xs_attacker maps)
  - Expected: Reassembly timeout → fragments dropped or limit armed
  
- **Fragment Offset Manipulation**: Non-sequential offsets
  - Reasm engines may queue out-of-order, stressing memory
  - Expected: Detection → drop_fragments flag
  
- **Overlapping Fragments**: Same offset, different payloads
  - RFC 815 overlap test; triggers reassembly engine parsing
  - Expected: DROP or reassembly error handling

#### 3. LAND & Anomaly Attacks
- **LAND**: src_ip == dst_ip
  - Confuses state machines expecting asymmetric routes
  - Expected: syn_flood + land_attack classification
  
- **Broadcast**: dst_ip = 255.255.255.255 or network broadcast
  - May bypass single-victim focusing; tests aggregation
  - Expected: icmp_flood or pass (valid in some contexts)

---

### B. Layer 4 (TCP/UDP) Bypass Vectors

#### 1. TCP Bad Flags
- **NULL**: All flags = 0
  - No SYN/ACK/FIN/RST; tests state machine robustness
  - Expected: DROP / bad_tcp_flags
  
- **XMAS**: FIN+PSH+URG
  - Classic port scanner evasion; tests flag validation
  - Expected: bad_tcp_flags classification
  
- **SYN+FIN**: Both state-initiating and terminating flags
  - Exploits simultaneous opening/closing; confuses TCP stacks
  - Expected: bad_tcp_flags or syn_flood (depending on detection logic)
  
- **RST+SYN**: Contradictory flags
  - Tests mutual exclusivity validation
  - Expected: bad_tcp_flags

#### 2. TCP State Exhaustion
- **SYN Flood (high rate)**: 50,000+ SYN/sec with spoofed sources
  - Fills connection tracking / SYN backlog
  - Tests: xs_attacker[src] map capacity → per-source limits
  - Expected: drop_syn or ratelimit flag arms; recovery time tracked
  
- **ACK Flood**: Unsolicited ACKs without prior SYN
  - Tests untracked connection handling
  - Expected: drop_ack / drop_untracked
  
- **RST Flood**: Unsolicited RSTs
  - Tests connection state validation
  - Expected: drop_untracked or rst_flood classification

#### 3. UDP Volumetric
- **Standard UDP Flood**: 1500B packets at max rate
  - Baseline DDoS vector; tests UDP drop policy
  - Expected: udp_flood classification → drop_udp flag
  
- **Tiny UDP Flood**: 0-byte UDP packets
  - Max PPS (packet rate) test; can exceed max BPS
  - Tests: Rate limiting on tiny packets (not byte-based)
  - Expected: udp_flood with high pps observed
  
- **Large UDP Flood**: 1400B+ packets
  - Max BPS (bandwidth) test; lower PPS but same threat
  - Expected: udp_flood + udp_strict flag
  
- **Spoofed UDP**: Random source IPs
  - Defeats per-source rate limits
  - Expected: drop_udp_strict or global_rl flags

---

### C. UDP Reflection/Amplification Vectors

Real-world reflector services abused for amplification attacks:

| Service | Port | Response Size | Amplification | Classification |
|---------|------|---------------|----------------|----------------|
| DNS | 53 | 1400B | 28-54× | dns_amplification |
| NTP | 123 | 468B | 556× | udp_reflection |
| SNMP | 161 | 1400B | 6× | udp_reflection |
| memcached | 11211 | 1400B | 10k-50k× | udp_reflection |
| CLDAP | 389 | 1200B | 56-70× | udp_reflection |
| Chargen | 19 | 1024B | 358× | udp_reflection |
| SSDP | 1900 | 360B | 30× | udp_reflection |

**Test method:** Inject UDP packets *from* these service ports (src port) with large payload, destined to victim. XDP classifier detects the response *shape* and classifies regardless of actual service.

---

### D. Layer 3 ICMP Variants

- **Echo Request (Type 8)**: Standard ping
  - Tests icmp_flood detection
  - Expected: icmp_flood classification

- **Timestamp Request (Type 13)**: Less common; old network diagnostic
  - Expected: icmp_flood (volume-based, not type-specific)

- **Unreachable (Type 3)**: ICMP errors; may bypass if untracked
  - Expected: icmp_flood

- **Redirect (Type 5)**: Route manipulation; exploits trusting implementations
  - Expected: icmp_flood

- **TTL Exceeded (Type 11)**: Traceroute response
  - Expected: icmp_flood

---

### E. IPv6 Extensions & Fragmentation

IPv6 adds extension headers (unlike IPv4 which uses IP flags for fragmentation):

- **Hop-by-Hop (Type 0)**: Allows per-hop options
  - Tests: Extension header parsing in XDP (notoriously fragile)
  - Expected: ipv6_ext_flood → drop_ipv6_ext flag

- **Destination Options (Type 60)**: End-to-end options
  - Similar to hop-by-hop
  - Expected: ipv6_ext_flood

- **IPv6 Fragmentation Header (Type 44)**: IPv6 version of IP fragmentation
  - Combined with tiny fragments (8 bytes each)
  - Tests: IPv6 reassembly pipeline (separate from IPv4)
  - Expected: ipv6_frag_flood or drop_fragments + drop_ipv6_ext

- **IPv6 UDP Flood**: UDP traffic over IPv6
  - Tests: IPv6 UDP classification (may differ from IPv4)
  - Expected: ipv6_flood + udp_flood or ipv6_udp_flood

- **IPv6 TCP SYN**: SYN flood over IPv6
  - Tests: TCP state tracking on IPv6
  - Expected: ipv6_flood + syn_flood or ipv6_syn_flood

---

### F. Multi-Vector & Composite Attacks

- **Carpet Bomb**: Simultaneous SYN + UDP + ICMP + Reflection
  - Tests: Multi-threaded classification and prioritization
  - Expected: Multiple types detected; global rate limit engaged

- **Temporal Ramp**: Gradual attack onset (slow ramp)
  - Tests: Detection latency under gradual escalation
  - Expected: Detector should catch threat before full rate reached

- **Spoofed Evasion**: All packets from randomized sources
  - Tests: Aggregate-level detection (per-src limits bypassed)
  - Expected: drop_udp_strict or global_rl flags (not per-src)

---

## Execution Steps

### Prerequisites

SSH into the target appliance:
```bash
ssh root@192.168.1.193
```

### Step 1: Pre-Test Validation

```bash
# Check XDP program is loaded
bpftool prog list | grep xdp

# Check maps are pinned
ls -la /sys/fs/bpf/xdp-sentinel/vlan10/

# Check metrics endpoint
curl http://127.0.0.1:9464/metrics | head -20

# Verify victim IP in config
cat /etc/xdp-sentinel/config.toml | grep victim
```

### Step 2: Run Baseline Tests (Monitor-Only)

These **must NOT trigger** detection:

```bash
cd /path/to/eBPF\ XDP
python3 pentest/xdp_pentest.py --coverage
python3 pentest/xdp_pentest.py --selftest
```

### Step 3: Execute Attack Vector Suite

Full 48-test suite (includes all bypass, stress, reflection, IPv6):

```bash
sudo python3 pentest/xdp_pentest.py --run
```

Single category (e.g., reflection attacks):

```bash
sudo python3 pentest/xdp_pentest.py --run --filter reflection
```

Single test (e.g., DNS amplification):

```bash
sudo python3 pentest/xdp_pentest.py --run --filter refl-dns
```

Repeat runs for statistical stability (flakiness detection):

```bash
sudo python3 pentest/xdp_pentest.py --run --repeat 3
```

Force spoofed sources (defeats per-src limits):

```bash
sudo python3 pentest/xdp_pentest.py --run --spoofed
```

### Step 4: Real-Time Monitoring During Tests

In a second terminal:

```bash
# Watch metrics (updates every ~1s)
watch 'curl -s http://127.0.0.1:9464/metrics | grep xs_'

# Watch kernel logs for drops
tail -f /var/log/kern.log | grep -E "DROP|xdp|sentinel"

# Monitor CPU & memory
top -d 1
```

### Step 5: Report & Analysis

```bash
# Automatic report generation (after --run)
cat pentest/results/latest.md

# Compare two runs for regressions
python3 pentest/xdp_pentest.py --compare results/run-A.json results/run-B.json

# JSON raw data (for custom analysis)
cat pentest/results/latest.json | jq '.aggregate'
```

---

## Expected Results & Success Criteria

### Detection Performance

- **Precision**: ≥95% (no false positives on benign traffic)
- **Recall**: ≥98% (catches all malicious vectors)
- **F1 Score**: ≥0.96
- **False Positive Rate**: <1%

### Classification Accuracy

Each attack vector should trigger the correct `xs_detection_info{type}`:
- Bypass attempts → malformed_flood
- TCP floods → syn_flood / ack_flood / rst_flood / fin_flood
- UDP → udp_flood / udp_reflection / dns_amplification
- ICMP → icmp_flood
- Fragments → frag_flood
- IPv6 extensions → ipv6_ext_flood

### Mitigation Response

Expected flags should **newly arm** (not already on at baseline):
- TCP attacks → drop_syn / drop_ack / drop_untracked / ratelimit
- UDP → drop_udp / drop_udp_strict
- ICMP → drop_icmp
- Fragments → drop_fragments
- IPv6 ext → drop_ipv6_ext

### Latencies

- **Detection**: <5 seconds from attack start
- **Classification**: <6 seconds
- **Mitigation**: <6 seconds (flags newly armed)
- **Recovery**: <30 seconds (threat returns to 0, flags lift)

### System Impact

- **Load Average**: <0.5 increase during attack
- **Memory**: Stable (no OOM or memory leaks)
- **Packet Loss**: Only intended drops (no collateral legitimate drops)

---

## Known Bypass Candidates & Edge Cases

These are **security-critical to test** but may surface implementation issues:

1. **Fragmentation Reassembly Exhaustion**
   - Sending 10,000+ fragments simultaneously
   - XDP may timeout incomplete reassemblies → memory grows unbounded
   - Expected: Timeout handling + drop_fragments flag
   - Bypass risk: If no limit, memory DoS possible

2. **TCP State Machine Edge Cases**
   - SYN+FIN, RST+SYN, ACK with seq=0
   - XDP may not validate all RFC 793 constraints
   - Expected: bad_tcp_flags classification
   - Bypass risk: If accepted, may establish invalid connections

3. **IPv6 Extension Header Chaining**
   - Multiple extension headers in sequence
   - Kernel parsing may be incomplete (eBPF limitations)
   - Expected: drop_ipv6_ext flag
   - Bypass risk: Complex chains may not be fully parsed

4. **Map Exhaustion via Spoofed Sources**
   - 100,000+ unique source IPs in SYN flood
   - xs_attacker[src] map has fixed size (typically 64k entries)
   - Expected: Per-source limits overflow → global_rl activates
   - Bypass risk: If map is full, new sources may pass through

5. **Reflection Misclassification**
   - Service-port heuristics may misclassify
   - A large-payload UDP from port 1234 reads as "dns_amplification"
   - Expected: Conservative classification
   - Bypass risk: Custom amplifiers on non-standard ports may bypass

---

## Metrics Captured

### Per-Test

| Metric | Meaning |
|--------|---------|
| `peak_threat` | Highest threat score observed (0-100) |
| `peak_pps` | Packets-per-second throughput observed |
| `detected` | Boolean: threat ≥ 2 (attack threshold) |
| `seen_types` | List of `xs_detection_info{type}` labels |
| `armed_flags` | List of newly-armed risk flags |
| `detection_latency` | Time from attack start to threat ≥ 2 |
| `classification_latency` | Time to first detection type |
| `mitigation_latency` | Time to first risk flag (e.g., drop_udp) |
| `recovery_time` | Time from last attack packet to threat=0 + flags lift |
| `drop_delta` | Packets dropped (xs_verdict_packets_total{verdict="drop"}) |
| `pass_delta` | Packets passed (xs_verdict_packets_total{verdict="pass"}) |

### Aggregate

| Metric | Meaning |
|--------|---------|
| `TP` | True Positives (attack detected & correct) |
| `FN` | False Negatives (attack missed) |
| `FP` | False Positives (benign incorrectly flagged) |
| `TN` | True Negatives (benign correctly allowed) |
| `precision` | TP / (TP + FP) — confidence in detections |
| `recall` | TP / (TP + FN) — completeness of detection |
| `F1` | 2×P×R / (P+R) — harmonic mean |
| `FPR` | FP / (FP + TN) — false alarm rate |

---

## Regression Detection

After each run, compare against baseline to catch regressions:

```bash
python3 pentest/xdp_pentest.py --compare baseline.json latest.json
```

This identifies:
- Tests that **passed before but now fail** (regression)
- Tests that **failed before but now pass** (fix)

---

## Remediation & Hardening

If bypasses are found:

1. **Malformed Headers**: Add strict BPF bounds checks on IHL, Total Length
2. **Fragmentation**: Implement timeout for incomplete reassemblies; limit max outstanding fragments
3. **TCP Flags**: Add RFC 793 validation (mutual exclusivity, sequence constraints)
4. **IPv6 Extensions**: Implement full extension header chain parsing (complex in eBPF)
5. **Map Exhaustion**: Monitor map usage; implement LRU eviction or hash collision handling
6. **Spoofing Evasion**: Transition from per-source to aggregate rate limiting (done via global_rl flag)

---

## References

- **xdp-sentinel README**: pentest/README.md (this project)
- **eBPF XDP Architecture**: docs/architecture.md
- **Policy Engine**: docs/policy-engine.md
- **Threat Model**: docs/threat-model.md
- **RFC 791 (IPv4)**, **RFC 2463 (ICMPv4)**, **RFC 3986 (IPv6)**
- **NIST SP 800-83 (Threat Modeling)**

