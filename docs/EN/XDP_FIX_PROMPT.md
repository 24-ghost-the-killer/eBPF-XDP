<!-- Language: **English** · [Dansk](../DK/XDP_FIX_PROMPT.md) -->

# XDP Firewall IPv6 Fragmentation Classification Fix Prompt

## Problem Statement

Your eBPF/XDP firewall has **ONE identified issue** (low-severity, cosmetic):

**IPv6 fragmentation attack packets are detected and dropped correctly, but are labeled as `malformed_flood` instead of the expected `ipv6_frag_flood`.**

### Current Behavior
- **Attack Detection**: ✅ WORKING (packets detected)
- **Attack Mitigation**: ✅ WORKING (packets dropped)
- **Risk Flags**: ✅ WORKING (global_rl, ratelimit armed)
- **Classification Label**: ❌ WRONG (says malformed_flood, should say ipv6_frag_flood)

### Impact
- Security: **ZERO** — packets are still dropped
- User Experience: **ZERO** — network works correctly
- Operations: **MINOR** — alert/telemetry shows wrong attack type
- Severity: **LOW** — cosmetic classification accuracy issue

---

## Root Cause Analysis

The IPv6 fragmentation detection logic in your eBPF classifier is treating IPv6 fragment headers the same as other malformed packets, rather than distinguishing them as a specific `ipv6_frag_flood` attack type.

### What to Find

Look in your eBPF source code (likely `ebpf/classify.rs` or `ebpf/detect.rs`) for:

1. **The detection logic that classifies IPv6 packets**
   - Function/section that handles IPv6 next-header fields
   - Code that checks for IPv6 extension headers
   - Specifically: code that processes IPv6 fragment header (next_header == 44)

2. **The current classification decision**
   - Where the code decides to emit `malformed_flood` label
   - Look for hardcoded string or enum value like `AttackType::MalformedFlood`

3. **The expected classification constant**
   - Look for `AttackType::Ipv6FragFlood` or similar enum variant
   - Check if it's already defined but never used

### Example Code Patterns to Search For

```rust
// IPv6 next-header values
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;

// Detection code (pseudo-code, find the actual implementation)
fn classify_ipv6(...) {
    // ... code that reads IPv6 header ...
    let next_header = ipv6_header.next_header;
    
    if next_header == 44 {  // Fragment header
        // CURRENT: Returns AttackType::MalformedFlood
        // NEEDED:  Should return AttackType::Ipv6FragFlood
    }
}
```

---

## Solution Approach

### Step 1: Locate the IPv6 Classification Code

**Search for:**
```
grep -r "ipv6_frag\|IPv6.*frag\|next_header.*44" ebpf/*.rs
grep -r "ipv6_ext_flood\|ipv6_flood" ebpf/*.rs
grep -r "MalformedFlood" ebpf/*.rs | grep -i ipv6
```

**Expected locations:**
- `ebpf/classify.rs` — packet classification logic
- `ebpf/detect.rs` — threat detection
- `ebpf/headers.rs` — packet header parsing
- Look for function names like: `classify_ipv6()`, `detect_ipv6()`, `parse_ipv6_ext()`

### Step 2: Understand the Current Logic

Find the section that looks something like:

```rust
fn classify_packet(pkt: &PacketData) -> AttackType {
    // ... IP version check ...
    if ip_version == 6 {  // IPv6
        // ... parse IPv6 header ...
        let next_header = get_ipv6_next_header(pkt);
        
        match next_header {
            44 => {  // Fragment header
                // PROBLEM: This returns MalformedFlood
                return AttackType::MalformedFlood;  // ❌ WRONG
            }
            0 | 43 | 60 => {  // Hop-by-Hop, Routing, Destination Options
                return AttackType::Ipv6ExtFlood;  // ✅ Correct for these
            }
            _ => return AttackType::Ipv6Flood;  // Other IPv6
        }
    }
}
```

### Step 3: Identify Available Attack Types

Search for the enum definition:

```rust
enum AttackType {
    SynFlood,
    AckFlood,
    UdpFlood,
    IcmpFlood,
    MalformedFlood,
    Ipv6ExtFlood,
    Ipv6Flood,
    IcmpV6Flood,
    // ... check if Ipv6FragFlood or similar exists ...
}
```

**Key Questions:**
1. Does `Ipv6FragFlood` already exist as an enum variant?
   - If YES → use it directly
   - If NO → add it to the enum

2. Does the pentest framework expect `ipv6_frag_flood` label?
   - Check `pentest/xdp_pentest.py` line 170-173 for expected classification
   - Look for `KNOWN_TYPES` list

### Step 4: Make the Fix

#### Option A: If `Ipv6FragFlood` Enum Variant Exists

Change:
```rust
// BEFORE:
44 => return AttackType::MalformedFlood;

// AFTER:
44 => return AttackType::Ipv6FragFlood;
```

#### Option B: If Attack Type Doesn't Exist

**Step 1:** Add the enum variant:
```rust
enum AttackType {
    // ... existing variants ...
    Ipv6Flood,
    IcmpV6Flood,
    Ipv6FragFlood,  // ← ADD THIS
}
```

**Step 2:** Implement the string representation:
```rust
impl AttackType {
    fn as_str(&self) -> &'static str {
        match self {
            // ... existing cases ...
            AttackType::Ipv6Flood => "ipv6_flood",
            AttackType::IcmpV6Flood => "icmpv6_flood",
            AttackType::Ipv6FragFlood => "ipv6_frag_flood",  // ← ADD THIS
        }
    }
}
```

**Step 3:** Update the classification logic:
```rust
44 => return AttackType::Ipv6FragFlood;
```

#### Option C: If Multiple IPv6 Headers Need Fixes

Check the pentest framework expectations:
```bash
grep -A 5 "ipv6.*frag" pentest/xdp_pentest.py
grep "expected_classification" pentest/xdp_pentest.py | grep ipv6
```

Expected from test framework (line 550):
```python
("ipv6-frag","ipv6/ipv6_frag_flood",...,
 expected_classification=["ipv6_ext_flood","ipv6_flood","frag_flood"],
```

This means the test accepts multiple labels (IPv6 extension, generic IPv6, or fragment). Adding `ipv6_frag_flood` would make it more specific.

### Step 5: Rebuild and Test

```bash
# 1. Rebuild the eBPF program
make clean
make build

# 2. Reload the XDP program
sudo ip link set dev vlan10 xdp off  # Detach old
sudo ip link set dev vlan10 xdp obj ebpf/xdp.o sec xdp  # Load new

# 3. Verify metrics endpoint still works
curl http://127.0.0.1:9464/metrics | head -20

# 4. Run the single failing test
cd pentest
sudo python3 xdp_pentest.py --run --filter ipv6-frag

# 5. Check result
grep "ipv6-frag" results/latest.md
```

### Step 6: Regression Testing

```bash
# Run full 48-test suite to ensure no regressions
sudo python3 xdp_pentest.py --run

# Compare to baseline
python3 xdp_pentest.py --compare <baseline.json> results/latest.json
```

---

## Implementation Checklist

- [ ] **Search**: Locate IPv6 classification code in ebpf/*.rs
- [ ] **Understand**: Trace the flow from IPv6 packet → AttackType enum
- [ ] **Identify**: Confirm if Ipv6FragFlood variant exists
- [ ] **Add**: If missing, add enum variant and string representation
- [ ] **Fix**: Change IPv6 fragment header (44) handling from MalformedFlood → Ipv6FragFlood
- [ ] **Rebuild**: `make build` and reload XDP program
- [ ] **Test Single**: Run `xdp_pentest.py --run --filter ipv6-frag`
- [ ] **Test All**: Run full `xdp_pentest.py --run` suite
- [ ] **Verify**: Check that IPv6 fragmentation test now shows correct label
- [ ] **Commit**: `git add ebpf/ && git commit -m "Fix IPv6 fragmentation classification label"`

---

## Code Search Commands

Use these to find the relevant code:

```bash
# Find IPv6 classification logic
grep -rn "ipv6\|IPv6" ebpf/*.rs | grep -i "classify\|detect\|next.header"

# Find fragment header handling (value 44)
grep -rn "44\|0x2c\|fragment" ebpf/*.rs

# Find AttackType enum
grep -rn "enum AttackType\|as_str\|to_string" ebpf/*.rs

# Find the specific malformed_flood classification
grep -rn "MalformedFlood\|malformed_flood" ebpf/*.rs

# Check what the test expects
grep -A 5 "ipv6-frag\|ipv6_frag" pentest/xdp_pentest.py
```

---

## Expected Outcome After Fix

**Before:**
```
[ipv6-frag] ipv6/ipv6_frag_flood ... FAIL (TP, det=1.1s, 
  types=malformed_flood,  # ← WRONG LABEL
  armed=global_rl,ratelimit)
```

**After:**
```
[ipv6-frag] ipv6/ipv6_frag_flood ... PASS (TP, det=1.1s, 
  types=ipv6_frag_flood,  # ← CORRECT LABEL
  armed=global_rl,ratelimit)
```

Full test suite result:
```
==== 48/48 passed | P=1.0 R=1.0 F1=1.0 FPR=0.0 ====
```

---

## Additional Considerations

### If You Can't Find the Code
The eBPF code structure might be different:
1. Check `ebpf/` directory listing: `ls -la ebpf/`
2. Search for Rust files: `find . -name "*.rs" | grep -E "ebpf|xdp"`
3. Check for different classification approach (bitmap flags vs enum)
4. Look for macro-based classification instead of function

### If Multiple Classification Issues Exist
Run the full test suite and note all FAILs:
```bash
sudo python3 pentest/xdp_pentest.py --run 2>&1 | grep "FAIL\|❌"
```

For each FAIL:
- Note the test name
- Note the expected vs actual classification
- Follow the same fix process

### If Fix Breaks Other Tests
Use git to revert:
```bash
git diff ebpf/
git checkout ebpf/  # Revert changes
```

Then review the logic more carefully. Likely causes:
1. IPv6 extension headers (0, 43, 60) getting misclassified
2. Fragment offset calculation affecting detection
3. Multiple extension headers in sequence not handled

---

## Files to Modify

Based on typical eBPF/XDP project structure:

**Primary Files:**
- `ebpf/classify.rs` or `ebpf/detect.rs` — classification logic
- `ebpf/headers.rs` — packet header parsing (if separate)

**May Also Need:**
- `ebpf/lib.rs` or `ebpf/main.rs` — enum definitions
- `userspace/agent.rs` — metric label mappings (might need update)

**Should NOT Need:**
- `pentest/xdp_pentest.py` — already accepts the correct labels
- `docs/` — documentation can be updated post-fix
- `Makefile` — build should work as-is

---

## Success Criteria

✅ **Test passes**: `ipv6-frag` test changes from FAIL to PASS  
✅ **Correct label**: Classification shows `ipv6_frag_flood` (or accepted variant)  
✅ **No regressions**: Full 48-test suite still passes  
✅ **Performance stable**: Detection/mitigation latencies unchanged  
✅ **Metrics correct**: Telemetry shows correct attack type  

---

## Questions? Need Help?

If the code structure is significantly different:
1. Share the output of: `ls -la ebpf/` and `grep -l "AttackType\|classify" ebpf/*.rs`
2. Share the first 50 lines of the main classification function
3. Note if eBPF code is in C, Rust, or another language

The fix pattern remains the same: find where IPv6 fragment header is detected, change the emitted label from generic/malformed to specific `ipv6_frag_flood`.

---

**Estimated Effort**: 15-30 minutes (search + modify + test)  
**Risk Level**: LOW (single label change, no logic flow change)  
**Rollback**: Simple (revert file with git)

