//! Phase 11 native classifier scorer.
//!
//! Loads the CART DDoS-classifier model produced by
//! `ml/train/train_classifier.py` and predicts a class-probability vector,
//! byte-identically to the Python trainer. Same portability contract as the
//! anomaly [`crate::iforest`] scorer: one model definition, two runtimes.

use serde_json::Value;

/// A loaded multiclass CART classifier.
#[derive(Debug)]
pub struct Classifier {
    schema_hash: String,
    classes: Vec<String>,
    medians: Vec<f64>,
    tree: Value,
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

impl Classifier {
    pub fn from_json(bytes: &[u8]) -> Result<Classifier, ModelError> {
        let v: Value = serde_json::from_slice(bytes)?;
        let schema_hash = v
            .get("schema_hash")
            .and_then(|x| x.as_str())
            .ok_or(ModelError::Field("schema_hash"))?
            .to_string();
        let classes = v
            .get("classes")
            .and_then(|x| x.as_array())
            .ok_or(ModelError::Field("classes"))?
            .iter()
            .map(|x| x.as_str().unwrap_or("").to_string())
            .collect();
        let medians = v
            .get("medians")
            .and_then(|x| x.as_array())
            .ok_or(ModelError::Field("medians"))?
            .iter()
            .map(|x| x.as_f64().unwrap_or(0.0))
            .collect();
        let tree = v.get("tree").ok_or(ModelError::Field("tree"))?.clone();
        Ok(Classifier { schema_hash, classes, medians, tree })
    }

    pub fn schema_hash(&self) -> &str {
        &self.schema_hash
    }
    pub fn classes(&self) -> &[String] {
        &self.classes
    }

    pub fn check_schema(&self, want: &str) -> Result<(), ModelError> {
        if self.schema_hash == want {
            Ok(())
        } else {
            Err(ModelError::SchemaMismatch { model: self.schema_hash.clone(), want: want.into() })
        }
    }

    /// Class-probability vector (aligned with [`classes`]).
    pub fn predict_proba(&self, vec: &[f64]) -> Vec<f64> {
        let mut node = &self.tree;
        while !node.get("leaf").and_then(|x| x.as_bool()).unwrap_or(false) {
            let f = node.get("f").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
            let t = node.get("t").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let mut x = vec.get(f).copied().unwrap_or(f64::NAN);
            if !x.is_finite() {
                x = self.medians.get(f).copied().unwrap_or(0.0);
            }
            let branch = if x < t { "l" } else { "r" };
            match node.get(branch) {
                Some(child) => node = child,
                None => break,
            }
        }
        node.get("p")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().map(|p| p.as_f64().unwrap_or(0.0)).collect())
            .unwrap_or_else(|| vec![0.0; self.classes.len()])
    }

    /// (predicted class, probability).
    pub fn predict(&self, vec: &[f64]) -> (String, f64) {
        let p = self.predict_proba(vec);
        let (i, &best) =
            p.iter().enumerate().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()).unwrap_or((0, &0.0));
        (self.classes.get(i).cloned().unwrap_or_default(), best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE: &str = r#"{
        "schema_hash": "deadbeef",
        "classes": ["benign", "syn_flood"],
        "medians": [0.0, 0.0],
        "tree": {"f": 0, "t": 1000.0,
                 "l": {"leaf": true, "p": [1.0, 0.0]},
                 "r": {"leaf": true, "p": [0.0, 1.0]}}
    }"#;

    #[test]
    fn routes_and_predicts() {
        let m = Classifier::from_json(INLINE.as_bytes()).unwrap();
        assert_eq!(m.predict(&[10.0, 0.0]).0, "benign");
        assert_eq!(m.predict(&[50000.0, 0.0]).0, "syn_flood");
        let p = m.predict_proba(&[50000.0, 0.0]);
        assert_eq!(p, vec![0.0, 1.0]);
    }

    #[test]
    fn nan_uses_median() {
        let m = Classifier::from_json(INLINE.as_bytes()).unwrap();
        // NaN -> median 0.0 -> left -> benign
        assert_eq!(m.predict(&[f64::NAN, 0.0]).0, "benign");
    }

    #[test]
    fn golden_trained_classifier_if_present() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ml/models/classifier/v1/model.json");
        let Ok(bytes) = std::fs::read(path) else { return };
        let m = Classifier::from_json(&bytes).unwrap();
        assert_eq!(m.schema_hash(), crate::features::schema_hash());
        // A strong SYN-flood-shaped vector must classify as syn_flood.
        let mut v = m.medians.clone();
        v[crate::features::index_of("pps").unwrap()] = 200_000.0;
        v[crate::features::index_of("tcp_syn_rate").unwrap()] = 195_000.0;
        v[crate::features::index_of("tcp_syn_share").unwrap()] = 0.98;
        v[crate::features::index_of("tcp_syn_ack_ratio").unwrap()] = 9000.0;
        v[crate::features::index_of("share_tcp").unwrap()] = 0.98;
        v[crate::features::index_of("dport_entropy").unwrap()] = 0.05;
        let (class, _p) = m.predict(&v);
        assert_eq!(class, "syn_flood", "classified as {class}");
    }
}
