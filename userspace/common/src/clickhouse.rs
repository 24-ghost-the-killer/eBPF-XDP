//! Phase 7 ClickHouse write path (buffering policy; the agent supplies the
//! HTTP transport).
//!
//! Detection and mitigation must never wait for ClickHouse, so rows go into a
//! bounded queue: batch per table, flush at [`FLUSH_ROWS`] rows or
//! [`FLUSH_INTERVAL_MS`], and on overflow drop the OLDEST batches and count the
//! dropped rows (`xs_clickhouse_dropped_rows_total`). The exit criterion's
//! "ClickHouse outage test" is [`tests::outage_drops_oldest_and_counts`].

use std::collections::VecDeque;

/// Flush when a table's pending batch reaches this many rows.
pub const FLUSH_ROWS: usize = 10_000;
/// Flush at least this often even below `FLUSH_ROWS`.
pub const FLUSH_INTERVAL_MS: u64 = 1_000;

/// A batch of already-serialised rows (JSONEachRow) destined for one table.
#[derive(Clone, Debug)]
pub struct Batch {
    pub table: String,
    pub rows: Vec<String>,
    pub bytes: usize,
}

impl Batch {
    pub fn new(table: impl Into<String>) -> Self {
        Batch { table: table.into(), rows: Vec::new(), bytes: 0 }
    }
    pub fn push_row(&mut self, json: String) {
        self.bytes += json.len() + 1;
        self.rows.push(json);
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    /// The HTTP body: one JSON object per line.
    pub fn body(&self) -> String {
        self.rows.join("\n")
    }
}

/// A bounded queue of batches awaiting insert. Overflow drops the oldest
/// batches (freshest data is the most useful during an incident) and the
/// dropped rows are counted, never silently lost.
#[derive(Debug)]
pub struct WriteQueue {
    queue: VecDeque<Batch>,
    bytes: usize,
    max_bytes: usize,
    max_batches: usize,
    dropped_rows: u64,
    dropped_batches: u64,
}

impl WriteQueue {
    /// `max_bytes` and `max_batches` are hard ceilings (whichever hits first).
    pub fn new(max_bytes: usize, max_batches: usize) -> Self {
        WriteQueue {
            queue: VecDeque::new(),
            bytes: 0,
            max_bytes,
            max_batches: max_batches.max(1),
            dropped_rows: 0,
            dropped_batches: 0,
        }
    }

    /// Enqueue a batch, evicting the oldest batches until within bounds.
    pub fn enqueue(&mut self, b: Batch) {
        if b.is_empty() {
            return;
        }
        self.bytes += b.bytes;
        self.queue.push_back(b);
        while self.bytes > self.max_bytes || self.queue.len() > self.max_batches {
            let Some(old) = self.queue.pop_front() else { break };
            self.bytes -= old.bytes;
            self.dropped_rows += old.len() as u64;
            self.dropped_batches += 1;
        }
    }

    /// Take the oldest batch to send. On send failure the caller re-enqueues
    /// it with [`requeue_front`], which re-applies the bound.
    pub fn dequeue(&mut self) -> Option<Batch> {
        let b = self.queue.pop_front();
        if let Some(ref b) = b {
            self.bytes -= b.bytes;
        }
        b
    }

    /// Put a batch back at the front after a failed send, honouring the bound
    /// (if it no longer fits, it is dropped and counted).
    pub fn requeue_front(&mut self, b: Batch) {
        self.bytes += b.bytes;
        self.queue.push_front(b);
        while self.bytes > self.max_bytes || self.queue.len() > self.max_batches {
            // Drop from the back here: we just restored the oldest, so the
            // newest is the one to shed if we are over the limit.
            let Some(new) = self.queue.pop_back() else { break };
            self.bytes -= new.bytes;
            self.dropped_rows += new.len() as u64;
            self.dropped_batches += 1;
        }
    }

    pub fn pending_batches(&self) -> usize {
        self.queue.len()
    }
    pub fn pending_bytes(&self) -> usize {
        self.bytes
    }
    pub fn dropped_rows(&self) -> u64 {
        self.dropped_rows
    }
    pub fn dropped_batches(&self) -> u64 {
        self.dropped_batches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(table: &str, rows: usize, row_bytes: usize) -> Batch {
        let mut b = Batch::new(table);
        for _ in 0..rows {
            b.push_row("x".repeat(row_bytes));
        }
        b
    }

    #[test]
    fn batch_body_is_json_each_line() {
        let mut b = Batch::new("xs.security_events");
        b.push_row(r#"{"a":1}"#.into());
        b.push_row(r#"{"a":2}"#.into());
        assert_eq!(b.body(), "{\"a\":1}\n{\"a\":2}");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn outage_drops_oldest_and_counts() {
        // Simulate a ClickHouse outage: nobody dequeues, batches pile up.
        // Bound: 1000 bytes. Each batch is 10 rows x 20 bytes ~= 210 bytes.
        let mut q = WriteQueue::new(1000, 100);
        for i in 0..20 {
            let mut b = batch("xs.traffic_windows", 10, 20);
            // tag first row so we can reason about ordering if needed
            b.rows[0] = format!("batch{i}");
            q.enqueue(b);
        }
        // Never exceeds the byte bound.
        assert!(q.pending_bytes() <= 1000, "bytes {}", q.pending_bytes());
        // Something was dropped, and it was counted (20 batches x 10 rows = 200
        // enqueued; at most ~4 batches fit in 1000 bytes).
        assert!(q.dropped_rows() > 0);
        assert_eq!(q.dropped_rows(), 200 - q.pending_batches() as u64 * 10);
        // The freshest batch survived (we drop the oldest).
        let mut last = None;
        while let Some(b) = q.dequeue() {
            last = Some(b.rows[0].clone());
        }
        assert_eq!(last, Some("batch19".to_string()));
    }

    #[test]
    fn batch_count_bound() {
        let mut q = WriteQueue::new(usize::MAX, 3);
        for _ in 0..10 {
            q.enqueue(batch("t", 1, 5));
        }
        assert_eq!(q.pending_batches(), 3);
        assert_eq!(q.dropped_batches(), 7);
    }

    #[test]
    fn empty_batch_ignored() {
        let mut q = WriteQueue::new(1000, 10);
        q.enqueue(Batch::new("t"));
        assert_eq!(q.pending_batches(), 0);
    }
}
