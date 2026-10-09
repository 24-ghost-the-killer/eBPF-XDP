"""Load the canonical feature schema (ml/feature_schema/v1.yaml).

The YAML is emitted from the Rust `xs_common::features::SCHEMA` so the feature
order and schema_hash are identical across the dataplane, the agent and the
training pipeline. This module parses it with the standard library only (no
PyYAML dependency) so it runs anywhere.
"""
from __future__ import annotations

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "feature_schema", "v1.yaml")


def load_schema(path: str = SCHEMA_PATH):
    """Return (feature_names, schema_hash)."""
    names, schema_hash = [], None
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = re.match(r"#\s*schema_hash:\s*([0-9a-f]{64})", line)
            if m:
                schema_hash = m.group(1)
            m = re.match(r"\s*-\s*name:\s*(\w+)", line)
            if m:
                names.append(m.group(1))
    if not names or schema_hash is None:
        raise RuntimeError(f"could not parse schema at {path}")
    return names, schema_hash


FEATURES, SCHEMA_HASH = load_schema()

if __name__ == "__main__":
    print(f"schema_hash = {SCHEMA_HASH}")
    print(f"{len(FEATURES)} features:")
    for n in FEATURES:
        print(f"  {n}")
