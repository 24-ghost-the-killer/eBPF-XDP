#!/usr/bin/env python3
"""Phase 10 anomaly model: Isolation Forest, trained on benign windows.

Self-contained (stdlib only) so it runs without sklearn/numpy/onnx. It trains
an Isolation Forest on the benign rows of the dataset and exports:

  * a portable JSON model (ml/models/anomaly/<version>/model.json) that the
    native Rust scorer (xs_common::iforest) loads with byte-identical results
    (the "ONNX parity" role: one model definition, two runtimes);
  * a manifest.json pinning schema_hash, params and metrics, so a run is
    reproducible and a model is only ever served against its own schema.

Metrics: PR-AUC of the anomaly score at separating attack from benign windows,
compared to a trivial pps-threshold baseline (the Phase 10 exit criterion:
beat the baseline on PR-AUC).

  python3 ml/train/train_anomaly.py --data ml/dataset/synthetic.csv \
      --version v1 --trees 128 --sample 256
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from schema import FEATURES, SCHEMA_HASH  # noqa: E402


def read_dataset(path):
    rows, labels = [], []
    with open(path) as fh:
        reader = csv.reader(fh)
        header = None
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if header is None:
                header = row
                idx = {n: header.index(n) for n in FEATURES}
                is_attack_i = header.index("is_attack")
                continue
            vec = []
            for n in FEATURES:
                cell = row[idx[n]]
                vec.append(float("nan") if cell == "" else float(cell))
            rows.append(vec)
            labels.append(int(row[is_attack_i]))
    return rows, labels


def column_medians(rows):
    med = []
    for j in range(len(FEATURES)):
        vals = sorted(r[j] for r in rows if not math.isnan(r[j]))
        med.append(vals[len(vals) // 2] if vals else 0.0)
    return med


def impute(vec, med):
    return [med[j] if math.isnan(v) else v for j, v in enumerate(vec)]


def c_factor(n):
    # Expected external-path length of an unsuccessful BST search (Isolation
    # Forest normalisation). 0 for n <= 1, matching the standard/sklearn.
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


def build_tree(data, depth, max_depth, rng):
    n = len(data)
    if depth >= max_depth or n <= 1:
        return {"leaf": True, "size": n}
    # pick a feature with non-degenerate range
    feats = list(range(len(FEATURES)))
    rng.shuffle(feats)
    for j in feats:
        col = [row[j] for row in data]
        lo, hi = min(col), max(col)
        if hi - lo > 1e-12:
            thr = rng.uniform(lo, hi)
            left = [r for r in data if r[j] < thr]
            right = [r for r in data if r[j] >= thr]
            if left and right:
                return {
                    "f": j,
                    "t": thr,
                    "l": build_tree(left, depth + 1, max_depth, rng),
                    "r": build_tree(right, depth + 1, max_depth, rng),
                }
    return {"leaf": True, "size": n}


def path_length(vec, node, depth):
    if node.get("leaf"):
        return depth + c_factor(node["size"])
    branch = node["l"] if vec[node["f"]] < node["t"] else node["r"]
    return path_length(vec, branch, depth + 1)


def score(vec, trees, c_n):
    avg = sum(path_length(vec, t, 0) for t in trees) / len(trees)
    return 2.0 ** (-avg / c_n)


def pr_auc(scores, labels):
    """Average precision (area under precision-recall), higher = better."""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    P = sum(labels)
    if P == 0:
        return float("nan")
    tp = 0
    fp = 0
    ap = 0.0
    prev_recall = 0.0
    for i in order:
        if labels[i]:
            tp += 1
        else:
            fp += 1
        recall = tp / P
        precision = tp / (tp + fp)
        ap += precision * (recall - prev_recall)
        prev_recall = recall
    return ap


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/dataset/synthetic.csv")
    ap.add_argument("--version", default="v1")
    ap.add_argument("--trees", type=int, default=128)
    ap.add_argument("--sample", type=int, default=256)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--outdir", default="ml/models/anomaly")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    rows, labels = read_dataset(args.data)
    benign = [r for r, y in zip(rows, labels) if y == 0]
    med = column_medians(benign)
    benign_imp = [impute(r, med) for r in benign]

    max_depth = math.ceil(math.log2(max(2, args.sample)))
    c_n = c_factor(args.sample)
    trees = []
    for _ in range(args.trees):
        sample = [benign_imp[rng.randrange(len(benign_imp))] for _ in range(min(args.sample, len(benign_imp)))]
        trees.append(build_tree(sample, 0, max_depth, rng))

    # metrics on the full dataset
    all_imp = [impute(r, med) for r in rows]
    scores = [score(v, trees, c_n) for v in all_imp]
    ap_model = pr_auc(scores, labels)
    # baseline: pps alone
    pps_i = FEATURES.index("pps")
    ap_base = pr_auc([r[pps_i] if not math.isnan(r[pps_i]) else 0.0 for r in rows], labels)

    outdir = os.path.join(args.outdir, args.version)
    os.makedirs(outdir, exist_ok=True)
    model = {
        "kind": "isolation_forest",
        "schema_hash": SCHEMA_HASH,
        "features": FEATURES,
        "medians": med,
        "sample_size": args.sample,
        "c_n": c_n,
        "trees": trees,
    }
    with open(os.path.join(outdir, "model.json"), "w") as fh:
        json.dump(model, fh)
    manifest = {
        "model": "anomaly_isolation_forest",
        "version": args.version,
        "schema_hash": SCHEMA_HASH,
        "trees": args.trees,
        "sample_size": args.sample,
        "seed": args.seed,
        "data": os.path.basename(args.data),
        "metrics": {"pr_auc": ap_model, "pr_auc_baseline_pps": ap_base},
    }
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)

    print(f"trained {args.trees} trees on {len(benign_imp)} benign windows")
    print(f"  PR-AUC model={ap_model:.4f}  baseline(pps)={ap_base:.4f}")
    print(f"  {'PASS' if ap_model >= ap_base else 'FAIL'}: beats baseline")
    print(f"  wrote {outdir}/model.json + manifest.json")


if __name__ == "__main__":
    main()
