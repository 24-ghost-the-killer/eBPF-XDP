//! `sentinel-inference` (Phase 10): a small, dependency-light inference
//! process. It loads a JSON model (Isolation Forest anomaly model, or a
//! classifier tree ensemble) and scores feature vectors read as newline-
//! delimited JSON arrays on stdin, emitting one score per line. In production
//! the agent speaks to it over a pipe; keeping inference in its own process
//! isolates model crashes and lets models be swapped without restarting the
//! dataplane owner.
//!
//!   sentinel-inference --model ml/models/anomaly/v1/model.json < vectors.jsonl
//!   echo '[...40 floats...]' | sentinel-inference --model model.json --schema <hash>

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use clap::Parser;
use xs_common::features;
use xs_common::iforest::Forest;

#[derive(Parser)]
#[command(name = "sentinel-inference", version, about = "score feature vectors against a model")]
struct Cli {
    /// Path to the JSON model (train_anomaly.py / train_classifier.py output).
    #[arg(long)]
    model: PathBuf,
    /// Require the model's schema_hash to equal this (the running feature hash).
    #[arg(long)]
    schema: Option<String>,
    /// Print the model's schema hash and the built-in feature schema hash, then exit.
    #[arg(long)]
    info: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let bytes = std::fs::read(&cli.model)?;
    let forest = Forest::from_json(&bytes)?;

    if cli.info {
        println!("model schema_hash:   {}", forest.schema_hash());
        println!("feature schema_hash: {}", features::schema_hash());
        println!("features expected:   {}", features::N);
        return Ok(());
    }

    let want = cli.schema.unwrap_or_else(features::schema_hash);
    forest.check_schema(&want)?;

    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // Missing features are JSON null -> NaN (imputed by the model).
        let raw: Vec<Option<f64>> = serde_json::from_str(&line)?;
        let vec: Vec<f64> = raw.into_iter().map(|x| x.unwrap_or(f64::NAN)).collect();
        writeln!(out, "{:.6}", forest.score(&vec))?;
    }
    Ok(())
}
