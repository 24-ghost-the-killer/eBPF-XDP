#!/usr/bin/env python3
"""Phase 11 DDoS classifier: multiclass CART over the feature vectors.

The design calls for LightGBM; that native dependency is not available in this
environment, so this trains a CART decision tree (Gini) with the identical
contract - portable JSON model, native Rust scorer (xs_common::classifier),
per-type recall on a held-out split - and the trainer swaps to a gradient-
boosted ensemble unchanged once the lab dataset and LightGBM are present.

Exit criterion: per-type recall >= 0.95 on the held-out split.

  python3 ml/train/train_classifier.py --data ml/dataset/synthetic.csv --version v1
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


def read(path):
    rows, labels = [], []
    with open(path) as fh:
        r = csv.reader(fh)
        header = None
        for row in r:
            if not row or row[0].startswith("#"):
                continue
            if header is None:
                header = row
                idx = {n: header.index(n) for n in FEATURES}
                at = header.index("attack_type")
                continue
            rows.append([float("nan") if row[idx[n]] == "" else float(row[idx[n]]) for n in FEATURES])
            labels.append(row[at])
    return rows, labels


def medians(rows):
    med = []
    for j in range(len(FEATURES)):
        v = sorted(r[j] for r in rows if not math.isnan(r[j]))
        med.append(v[len(v) // 2] if v else 0.0)
    return med


def gini(counts, n):
    if n == 0:
        return 0.0
    return 1.0 - sum((c / n) ** 2 for c in counts.values())


def class_counts(idxs, y):
    c = {}
    for i in idxs:
        c[y[i]] = c.get(y[i], 0) + 1
    return c


def best_split(idxs, X, y, rng):
    n = len(idxs)
    parent = gini(class_counts(idxs, y), n)
    best = None
    feats = list(range(len(FEATURES)))
    rng.shuffle(feats)
    for j in feats[:8]:  # subsample features for speed
        vals = sorted({X[i][j] for i in idxs})
        if len(vals) < 2:
            continue
        # up to 8 candidate thresholds spread over the observed values
        cands = [(_a + _b) / 2 for _a, _b in zip(vals, vals[1:])]
        if len(cands) > 8:
            step = max(1, len(cands) // 8)
            cands = cands[::step]
        for t in cands:
            left, right = [], []
            for i in idxs:  # single pass
                (left if X[i][j] < t else right).append(i)
            if not left or not right:
                continue
            g = (len(left) * gini(class_counts(left, y), len(left))
                 + len(right) * gini(class_counts(right, y), len(right))) / n
            if best is None or g < best[0]:
                best = (g, j, t, left, right)
    if best and best[0] < parent - 1e-9:
        return best
    return None


def majority(idxs, y, classes):
    c = class_counts(idxs, y)
    probs = [c.get(cl, 0) / len(idxs) for cl in classes]
    return probs


def build(idxs, X, y, classes, depth, max_depth, min_leaf, rng):
    if depth >= max_depth or len(idxs) < 2 * min_leaf:
        return {"leaf": True, "p": majority(idxs, y, classes)}
    s = best_split(idxs, X, y, rng)
    if s is None or len(s[3]) < min_leaf or len(s[4]) < min_leaf:
        return {"leaf": True, "p": majority(idxs, y, classes)}
    _, j, t, left, right = s
    return {
        "f": j, "t": t,
        "l": build(left, X, y, classes, depth + 1, max_depth, min_leaf, rng),
        "r": build(right, X, y, classes, depth + 1, max_depth, min_leaf, rng),
    }


def predict(vec, node, med):
    while not node.get("leaf"):
        x = vec[node["f"]]
        if math.isnan(x):
            x = med[node["f"]]
        node = node["l"] if x < node["t"] else node["r"]
    return node["p"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/dataset/synthetic.csv")
    ap.add_argument("--version", default="v1")
    ap.add_argument("--max-depth", type=int, default=12)
    ap.add_argument("--min-leaf", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--outdir", default="ml/models/classifier")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    X, y = read(args.data)
    med = medians(X)
    Ximp = [[med[j] if math.isnan(v) else v for j, v in enumerate(r)] for r in X]
    classes = sorted(set(y))

    idx = list(range(len(Ximp)))
    rng.shuffle(idx)
    cut = int(0.7 * len(idx))
    train_idx, test_idx = idx[:cut], idx[cut:]

    tree = build(train_idx, Ximp, y, classes, 0, args.max_depth, args.min_leaf, rng)

    # per-class recall on the test split
    from collections import defaultdict
    tp = defaultdict(int)
    tot = defaultdict(int)
    for i in test_idx:
        probs = predict(Ximp[i], tree, med)
        pred = classes[max(range(len(classes)), key=lambda k: probs[k])]
        tot[y[i]] += 1
        if pred == y[i]:
            tp[y[i]] += 1
    recalls = {c: (tp[c] / tot[c] if tot[c] else float("nan")) for c in classes}
    worst = min(r for r in recalls.values() if not math.isnan(r))

    outdir = os.path.join(args.outdir, args.version)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "model.json"), "w") as fh:
        json.dump({"kind": "cart_classifier", "schema_hash": SCHEMA_HASH,
                   "features": FEATURES, "medians": med, "classes": classes,
                   "tree": tree}, fh)
    with open(os.path.join(outdir, "manifest.json"), "w") as fh:
        json.dump({"model": "ddos_classifier_cart", "version": args.version,
                   "schema_hash": SCHEMA_HASH, "classes": classes,
                   "metrics": {"per_class_recall": recalls, "worst_recall": worst}},
                  fh, indent=2)

    print(f"trained CART on {len(train_idx)} rows, tested on {len(test_idx)}")
    for c in classes:
        print(f"  recall {c:<18} {recalls[c]:.3f}")
    print(f"  worst per-class recall = {worst:.3f}  "
          f"{'PASS' if worst >= 0.95 else 'FAIL'} (>= 0.95)")


if __name__ == "__main__":
    main()
