//! Phase 12 native bot-detector scorer.
//!
//! Loads the logistic-regression model from `ml/train/train_bot.py` and scores
//! a per-source feature vector to a bot probability in `[0, 1]`, byte-
//! identically to the Python trainer (same portability contract as the other
//! model scorers). Standardises with the stored mean/std before the linear
//! term, exactly as during training.

use serde_json::Value;

/// A loaded logistic-regression model.
#[derive(Debug)]
pub struct Logistic {
    features: Vec<String>,
    mean: Vec<f64>,
    std: Vec<f64>,
    weights: Vec<f64>,
    bias: f64,
    threshold: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("model JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("model field {0} missing or wrong type")]
    Field(&'static str),
}

fn arr(v: &Value, k: &'static str) -> Result<Vec<f64>, ModelError> {
    Ok(v.get(k)
        .and_then(|x| x.as_array())
        .ok_or(ModelError::Field(k))?
        .iter()
        .map(|x| x.as_f64().unwrap_or(0.0))
        .collect())
}

impl Logistic {
    pub fn from_json(bytes: &[u8]) -> Result<Logistic, ModelError> {
        let v: Value = serde_json::from_slice(bytes)?;
        Ok(Logistic {
            features: v
                .get("features")
                .and_then(|x| x.as_array())
                .ok_or(ModelError::Field("features"))?
                .iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect(),
            mean: arr(&v, "mean")?,
            std: arr(&v, "std")?,
            weights: arr(&v, "weights")?,
            bias: v.get("bias").and_then(|x| x.as_f64()).ok_or(ModelError::Field("bias"))?,
            threshold: v.get("threshold").and_then(|x| x.as_f64()).unwrap_or(0.5),
        })
    }

    pub fn features(&self) -> &[String] {
        &self.features
    }
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Bot probability in `[0, 1]` for a per-source feature vector (in the
    /// order of [`features`]).
    pub fn score(&self, vec: &[f64]) -> f64 {
        let mut z = self.bias;
        for j in 0..self.weights.len() {
            let x = vec.get(j).copied().unwrap_or(self.mean.get(j).copied().unwrap_or(0.0));
            let x = if x.is_finite() { x } else { self.mean.get(j).copied().unwrap_or(0.0) };
            let sd = self.std.get(j).copied().unwrap_or(1.0).max(1e-9);
            let xs = (x - self.mean.get(j).copied().unwrap_or(0.0)) / sd;
            z += self.weights[j] * xs;
        }
        sigmoid(z)
    }

    /// True if the source is classified as a bot at the model's threshold.
    pub fn is_bot(&self, vec: &[f64]) -> bool {
        self.score(vec) >= self.threshold
    }
}

fn sigmoid(z: f64) -> f64 {
    if z < -30.0 {
        0.0
    } else if z > 30.0 {
        1.0
    } else {
        1.0 / (1.0 + (-z).exp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_trained_bot_model_if_present() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ml/models/bot/v1/model.json");
        let Ok(bytes) = std::fs::read(path) else { return };
        let m = Logistic::from_json(&bytes).unwrap();
        // src_pps, src_syn_share, src_iat_cv, src_distinct_dports,
        // src_pkt_size_mode_share, src_bad_share
        let bot = [2000.0, 0.8, 0.05, 2.0, 0.9, 0.1];
        let human = [50.0, 0.05, 0.8, 15.0, 0.2, 0.01];
        let sb = m.score(&bot);
        let sh = m.score(&human);
        // Golden values from train_bot.py (seed 1).
        assert!((sb - 0.9937594787).abs() < 1e-6, "bot {sb}");
        assert!((sh - 0.0058979078).abs() < 1e-6, "human {sh}");
        assert!(m.is_bot(&bot));
        assert!(!m.is_bot(&human));
    }
}
