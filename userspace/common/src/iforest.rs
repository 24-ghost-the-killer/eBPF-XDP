//! Phase 10 native Isolation Forest scorer.
//!
//! Loads the portable JSON model produced by `ml/train/train_anomaly.py` and
//! scores feature vectors with results byte-identical to the Python trainer
//! (the "ONNX parity" role: one model definition, two runtimes, no Python in
//! production). The anomaly score is in `[0, 1]`; higher = more anomalous.
//!
//! Missing features (NaN) are imputed with the per-feature medians stored in
//! the model, exactly as during training. The model carries the feature
//! `schema_hash`; [`Forest::check_schema`] refuses a vector from another
//! schema.

use serde_json::Value;

/// Expected external-path length of an unsuccessful BST search (the IF
/// normalisation), 0 for n <= 1. Matches `c_factor` in the trainer.
fn c_factor(n: f64) -> f64 {
    if n <= 1.0 {
        return 0.0;
    }
    2.0 * ((n - 1.0).ln() + 0.577_215_664_9) - (2.0 * (n - 1.0) / n)
}

/// A loaded Isolation Forest model.
#[derive(Debug)]
pub struct Forest {
    schema_hash: String,
    medians: Vec<f64>,
    c_n: f64,
    trees: Vec<Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("model field {0} missing or wrong type")]
    Field(&'static str),
    #[error("model schema_hash {model} != feature schema {want}")]
    SchemaMismatch { model: String, want: String },
}

impl Forest {
    /// Parse a model from its JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Forest, ModelError> {
        let v: Value = serde_json::from_slice(bytes)?;
        let schema_hash = v
            .get("schema_hash")
            .and_then(|x| x.as_str())
            .ok_or(ModelError::Field("schema_hash"))?
            .to_string();
        let medians = v
            .get("medians")
            .and_then(|x| x.as_array())
            .ok_or(ModelError::Field("medians"))?
            .iter()
            .map(|x| x.as_f64().unwrap_or(0.0))
            .collect();
        let c_n = v.get("c_n").and_then(|x| x.as_f64()).ok_or(ModelError::Field("c_n"))?;
        let trees =
            v.get("trees").and_then(|x| x.as_array()).ok_or(ModelError::Field("trees"))?.clone();
        Ok(Forest { schema_hash, medians, c_n, trees })
    }

    pub fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    /// Error unless the model was trained on `want` (the running feature hash).
    pub fn check_schema(&self, want: &str) -> Result<(), ModelError> {
        if self.schema_hash == want {
            Ok(())
        } else {
            Err(ModelError::SchemaMismatch { model: self.schema_hash.clone(), want: want.into() })
        }
    }

    fn path_length(&self, vec: &[f64], node: &Value, depth: f64) -> f64 {
        if node.get("leaf").and_then(|x| x.as_bool()).unwrap_or(false) {
            let size = node.get("size").and_then(|x| x.as_f64()).unwrap_or(1.0);
            return depth + c_factor(size);
        }
        let f = node.get("f").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
        let t = node.get("t").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let x = self.value(vec, f);
        let branch = if x < t { "l" } else { "r" };
        match node.get(branch) {
            Some(child) => self.path_length(vec, child, depth + 1.0),
            None => depth,
        }
    }

    fn value(&self, vec: &[f64], f: usize) -> f64 {
        let x = vec.get(f).copied().unwrap_or(f64::NAN);
        if x.is_finite() {
            x
        } else {
            self.medians.get(f).copied().unwrap_or(0.0)
        }
    }

    /// Anomaly score in `[0, 1]`; higher = more anomalous.
    pub fn score(&self, vec: &[f64]) -> f64 {
        if self.trees.is_empty() || self.c_n <= 0.0 {
            return 0.0;
        }
        let sum: f64 = self.trees.iter().map(|t| self.path_length(vec, t, 0.0)).sum();
        let avg = sum / self.trees.len() as f64;
        2f64.powf(-avg / self.c_n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inline model whose scores can be computed by hand, pinning the Rust
    // path-length / score math to the trainer's formula (parity).
    const INLINE: &str = r#"{
        "schema_hash": "deadbeef",
        "features": ["a", "b"],
        "medians": [0.0, 0.0],
        "c_n": 4.0,
        "trees": [
            {"f": 0, "t": 5.0, "l": {"leaf": true, "size": 1}, "r": {"leaf": true, "size": 16}}
        ]
    }"#;

    #[test]
    fn parity_hand_computed() {
        let m = Forest::from_json(INLINE.as_bytes()).unwrap();
        // vec[0]=3 < 5 -> left leaf size 1 -> path = 1 + c(1) = 1; score = 2^(-1/4)
        let s_left = m.score(&[3.0, 0.0]);
        assert!((s_left - 2f64.powf(-0.25)).abs() < 1e-9, "left {s_left}");
        // vec[0]=9 -> right leaf size 16 -> path = 1 + c(16); score = 2^(-path/4)
        let path = 1.0 + c_factor(16.0);
        let s_right = m.score(&[9.0, 0.0]);
        assert!((s_right - 2f64.powf(-path / 4.0)).abs() < 1e-9, "right {s_right}");
        // more-anomalous (shorter path) scores higher
        assert!(s_left > s_right);
    }

    #[test]
    fn nan_imputed_with_median() {
        let m = Forest::from_json(INLINE.as_bytes()).unwrap();
        // NaN in feature 0 -> imputed with median 0.0 -> 0 < 5 -> left branch.
        let s_nan = m.score(&[f64::NAN, 0.0]);
        let s_zero = m.score(&[0.0, 0.0]);
        assert!((s_nan - s_zero).abs() < 1e-12);
    }

    #[test]
    fn schema_guard() {
        let m = Forest::from_json(INLINE.as_bytes()).unwrap();
        assert!(m.check_schema("deadbeef").is_ok());
        assert!(m.check_schema("other").is_err());
    }

    // Best-effort golden test against the real trained model, when present.
    #[test]
    fn golden_trained_model_if_present() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ml/models/anomaly/v1/model.json");
        let Ok(bytes) = std::fs::read(path) else {
            return; // model not trained in this checkout; skip
        };
        let m = Forest::from_json(&bytes).unwrap();
        let benign = m.medians.clone();
        let mut attack = m.medians.clone();
        // pps is feature 2, tcp_syn_rate feature 6 (see feature schema order).
        attack[2] = 500_000.0;
        attack[6] = 480_000.0;
        let sb = m.score(&benign);
        let sa = m.score(&attack);
        // Golden values from the Python trainer (train_anomaly.py, seed 1).
        assert!((sb - 0.3605627788).abs() < 1e-6, "benign {sb}");
        assert!((sa - 0.4115400082).abs() < 1e-6, "attack {sa}");
        assert!(sa > sb);
    }
}
