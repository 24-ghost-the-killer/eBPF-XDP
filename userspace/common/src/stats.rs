//! Counter snapshots.
//!
//! The dataplane keeps one `struct xs_stats` per CPU. A lookup of the single
//! element of the PERCPU_ARRAY returns every CPU's copy; a snapshot is their
//! sum. Reading is not atomic across CPUs (each CPU's block is copied while
//! that CPU may be incrementing it), so cross-counter invariants such as
//! `rx == pass + drop` hold exactly only on an idle dataplane and to within
//! the in-flight packets otherwise.

use crate::abi::{AbiError, Counter, CNT_SLOTS, COUNTER_SIZE, STATS_SIZE};

/// Sum of all CPUs' counters at one point in time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    counters: [Counter; CNT_SLOTS],
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot { counters: [Counter::default(); CNT_SLOTS] }
    }
}

impl Snapshot {
    /// Build from the per-CPU values returned by a PERCPU_ARRAY lookup
    /// (one `STATS_SIZE` buffer per possible CPU).
    pub fn from_percpu<B: AsRef<[u8]>>(per_cpu: &[B]) -> Result<Self, AbiError> {
        let mut snap = Snapshot::default();
        for value in per_cpu {
            let value = value.as_ref();
            if value.len() != STATS_SIZE {
                return Err(AbiError::Size {
                    what: "xs_stats",
                    expected: STATS_SIZE,
                    got: value.len(),
                });
            }
            for (slot, chunk) in value.chunks_exact(COUNTER_SIZE).enumerate() {
                let c = Counter::from_ne_bytes(chunk.try_into().expect("chunks_exact"));
                let acc = &mut snap.counters[slot];
                // Wrapping: a per-CPU u64 cannot realistically wrap, but the
                // sum must never panic in debug builds either.
                acc.packets = acc.packets.wrapping_add(c.packets);
                acc.bytes = acc.bytes.wrapping_add(c.bytes);
            }
        }
        Ok(snap)
    }

    pub fn get(&self, slot: usize) -> Counter {
        self.counters.get(slot).copied().unwrap_or_default()
    }

    /// Per-slot wrap-safe difference `self - earlier`.
    pub fn delta_since(&self, earlier: &Snapshot) -> Snapshot {
        let mut out = Snapshot::default();
        for (i, c) in out.counters.iter_mut().enumerate() {
            *c = self.counters[i].wrapping_sub(earlier.counters[i]);
        }
        out
    }

    /// Iterate over `(slot, counter)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, Counter)> + '_ {
        self.counters.iter().copied().enumerate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_block(entries: &[(usize, u64, u64)]) -> Vec<u8> {
        let mut v = vec![0u8; STATS_SIZE];
        for &(slot, p, b) in entries {
            v[slot * 16..slot * 16 + 8].copy_from_slice(&p.to_ne_bytes());
            v[slot * 16 + 8..slot * 16 + 16].copy_from_slice(&b.to_ne_bytes());
        }
        v
    }

    #[test]
    fn sums_cpus() {
        let cpus = vec![cpu_block(&[(0, 10, 1000), (65, 1, 60)]), cpu_block(&[(0, 5, 500)])];
        let s = Snapshot::from_percpu(&cpus).unwrap();
        assert_eq!(s.get(0), Counter { packets: 15, bytes: 1500 });
        assert_eq!(s.get(65), Counter { packets: 1, bytes: 60 });
        assert_eq!(s.get(999), Counter::default());
    }

    #[test]
    fn rejects_wrong_value_size() {
        let err = Snapshot::from_percpu(&[vec![0u8; 100]]).unwrap_err();
        assert!(matches!(err, AbiError::Size { got: 100, .. }));
    }

    #[test]
    fn delta() {
        let a = Snapshot::from_percpu(&[cpu_block(&[(0, 10, 100)])]).unwrap();
        let b = Snapshot::from_percpu(&[cpu_block(&[(0, 25, 400)])]).unwrap();
        assert_eq!(b.delta_since(&a).get(0), Counter { packets: 15, bytes: 300 });
    }
}
