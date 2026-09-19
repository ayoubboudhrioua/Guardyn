"""Turn recorded traces into a defensible escalation threshold.

Split conformal prediction over *decisions*, not scenarios: with 28 scenarios the
scenario-level sample is far too small to support a 95% claim, but each scenario
contributes several decisions. Report the n you actually used - a threshold quoted
without its sample size is not evidence.

    python tools/calibrate.py observability/decisions.jsonl --alpha 0.05
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def load(paths: list[Path]) -> list[dict]:
    rows = []
    for p in paths:
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("traces", nargs="+", type=Path)
    ap.add_argument("--alpha", type=float, default=0.05, help="tolerated over-block rate on benign decisions")
    args = ap.parse_args()

    rows = load(args.traces)
    benign = [r["risk"] for r in rows if not r.get("signals")]
    if not benign:
        print("no clean decisions found; run the benign scenarios first")
        return

    benign.sort()
    n = len(benign)
    # Conformal quantile with finite-sample correction.
    k = math.ceil((n + 1) * (1 - args.alpha))
    threshold = benign[min(k, n) - 1] if n else 1.0

    print(f"clean decisions observed      n = {n}")
    print(f"tolerated over-block rate     alpha = {args.alpha}")
    print(f"conformal escalation threshold      {threshold:.4f}")
    print(f"max clean risk observed             {benign[-1]:.4f}")
    print()
    print("Quote this as: escalation set so that the over-block rate on benign")
    print(f"decisions is at most {args.alpha:.0%}, with {n} calibration decisions.")


if __name__ == "__main__":
    main()
