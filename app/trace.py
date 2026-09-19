"""Sidecar observability trace.

The simulator's own JSONL records the decision but drops the defense's `metadata`,
so the reasoning behind a decision is not in it. We write our own append-only
record per decision - signals, weights, the exact evidence span - and merge it with
the simulator trace by (run_id, step_id). That merged file is what the dashboard
reads and what the video is narrated from.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

_LOCK = threading.Lock()
TRACE_PATH = Path(os.environ.get("SENTINEL_TRACE", "observability/decisions.jsonl"))


def record(entry: dict) -> None:
    entry = {"ts": datetime.now(UTC).isoformat(), **entry}
    with _LOCK:
        TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with TRACE_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str, sort_keys=True) + "\n")


def read_all() -> list[dict]:
    if not TRACE_PATH.exists():
        return []
    out = []
    for line in TRACE_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
