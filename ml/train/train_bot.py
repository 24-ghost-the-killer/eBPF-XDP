#!/usr/bin/env python3
"""Phase 12 bot detector: logistic regression over per-source features.

The bot detector scores an individual source (an admitted heavy hitter) as
bot-like vs human-like from the per-source feature block of feature-schema.md.
That per-source feature pipeline (Phase 5 heavy hitters + per-source windows)
is a follow-on, so there is no captured per-source dataset yet; this trains and
evaluates on a self-contained synthetic per-source set (machine-paced bots vs
bursty humans), with the same portable-JSON / native-Rust-scorer contract as
the other models. Swap in real per-source rows when the pipeline lands.

Exit criterion: precision >= 0.9 at the operating point on held-out data.

  python3 ml/train/train_bot.py --version v1
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random

# Per-source feature block (subset of feature-schema.md "source" scope).
SRC_FEATURES = [
    "src_pps",
    "src_syn_share",
    "src_iat_cv",              # inter-arrival CV: low = machine-paced
    "src_distinct_dports",
    "src_pkt_size_mode_share",  # high = one repeated size (generator)
    "src_bad_share",
]


def gen_source(is_bot: bool, rng: random.Random):
    if is_bot:
        return [
            rng.gauss(2000, 800),               # high pps
            rng.uniform(0.4, 1.0),              # SYN-heavy
            max(0.001, rng.gauss(0.05, 0.03)),  # very regular timing
            rng.uniform(1, 4),                  # few destination ports
            rng.uniform(0.7, 1.0),              # repeated packet size
            rng.uniform(0.0, 0.4),
        ]
    return [
        max(0.0, rng.gauss(50, 40)),            # modest pps
        rng.uniform(0.0, 0.2),
        max(0.05, rng.gauss(0.8, 0.3)),         # bursty human timing
        rng.uniform(2, 30),                     # varied ports
        rng.uniform(0.0, 0.4),                  # varied sizes
        rng.uniform(0.0, 0.05),
    ]


def sigmoid(z):
    if z < -30:
        return 0.0
    if z > 30:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1")
    ap.add_argument("--n", type=int, default=4000)
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--outdir", default="ml/models/bot")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    X, y = [], []
    for _ in range(args.n):
        bot = rng.random() < 0.5
        X.append(gen_source(bot, rng))
        y.append(1 if bot else 0)

    d = len(SRC_FEATURES)
    # standardise
    mean = [sum(r[j] for r in X) / len(X) for j in range(d)]
    std = [max(1e-6, math.sqrt(sum((r[j] - mean[j]) ** 2 for r in X) / len(X))) for j in range(d)]
    Xs = [[(r[j] - mean[j]) / std[j] for j in range(d)] for r in X]

    cut = int(0.7 * len(Xs))
    Xtr, ytr, Xte, yte = Xs[:cut], y[:cut], Xs[cut:], y[cut:]

    w = [0.0] * d
    b = 0.0
    for _ in range(args.epochs):
        gw = [0.0] * d
        gb = 0.0
        for xi, yi in zip(Xtr, ytr):
            p = sigmoid(sum(w[j] * xi[j] for j in range(d)) + b)
            err = p - yi
            for j in range(d):
                gw[j] += err * xi[j]
            gb += err
        n = len(Xtr)
        for j in range(d):
            w[j] -= args.lr * gw[j] / n
        b -= args.lr * gb / n

    # precision/recall on held-out at the operating threshold
    tp = fp = fn = 0
    for xi, yi in zip(Xte, yte):
        p = sigmoid(sum(w[j] * xi[j] for j in range(d)) + b)
        pred = 1 if p >= args.threshold else 0
        if pred == 1 and yi == 1:
            tp += 1
        elif pred == 1 and yi == 0:
            fp += 1
        elif pred == 0 and yi == 1:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")

    outdir = os.path.join(args.outdir, args.version)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "model.json"), "w") as fh:
        json.dump({"kind": "logistic", "features": SRC_FEATURES,
                   "mean": mean, "std": std, "weights": w, "bias": b,
                   "threshold": args.threshold}, fh)
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump({"model": "bot_detector_logistic", "version": args.version,
                   "features": SRC_FEATURES, "threshold": args.threshold,
                   "metrics": {"precision": precision, "recall": recall}}, fh, indent=2)

    print(f"trained logistic bot detector on {len(Xtr)} sources")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  "
          f"{'PASS' if precision >= 0.9 else 'FAIL'} (precision >= 0.9)")


if __name__ == "__main__":
    main()
