"""Small Ollama client for the model-backed layers (L4, L5).

Rules that keep it safe to sit inside a 5 s decision timeout:
  * a shared `Budget` deadline, so one slow call cannot starve the rest of the decision
  * greedy decoding, thinking off, JSON output: same input, same answer
  * a cache, so a repeated question is free
  * a circuit breaker, so a dead server costs one timeout rather than one per decision
  * every failure returns None; the caller treats that as "no flag", never as "attack"
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

import httpx

HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
if not HOST.startswith("http"):
    HOST = "http://" + HOST
MODEL = os.environ.get("GUARDYN_JUDGE_MODEL", os.environ.get("ISNAD_JUDGE_MODEL", "qwen3:8b"))
ENABLED = os.environ.get("GUARDYN_LLM", "on").lower() not in ("off", "0", "false")
BUDGET_S = float(os.environ.get("GUARDYN_LLM_BUDGET_S", "2.5"))

_LOCK = threading.Lock()
_CACHE: dict[str, dict] = {}
_FAILS = 0
_OPEN_UNTIL = 0.0


class Budget:
    """A wall-clock allowance shared by every model call in one decision."""

    def __init__(self, seconds: float = BUDGET_S) -> None:
        self.deadline = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())


def available() -> bool:
    return ENABLED and time.monotonic() >= _OPEN_UNTIL


def _trip() -> None:
    global _FAILS, _OPEN_UNTIL
    with _LOCK:
        _FAILS += 1
        if _FAILS >= 2:
            _OPEN_UNTIL = time.monotonic() + 30.0
            _FAILS = 0


def chat_json(system: str, user: str, budget: Budget, num_predict: int = 120) -> dict | None:
    """One JSON answer from the local model, or None (disabled, slow, unreachable, malformed)."""
    global _FAILS
    if not available():
        return None
    key = hashlib.sha256(f"{MODEL}\x00{system}\x00{user}".encode()).hexdigest()
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
    timeout = budget.remaining()
    if timeout < 0.3:
        return None
    body = {
        "model": MODEL,
        "stream": False,
        "think": False,
        "format": "json",
        "keep_alive": "30m",
        "options": {"temperature": 0, "seed": 0, "num_predict": num_predict},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    try:
        r = httpx.post(f"{HOST}/api/chat", json=body, timeout=timeout)
        r.raise_for_status()
        out = json.loads(r.json()["message"]["content"])
        if not isinstance(out, dict):
            return None
    except (httpx.HTTPError, ValueError, KeyError):
        _trip()
        return None
    with _LOCK:
        _FAILS = 0
        if len(_CACHE) > 512:
            _CACHE.clear()
        _CACHE[key] = out
    return out


def datamark(text: str, marker: str = "^") -> str:
    """Spotlighting: interleave a marker between words so untrusted text cannot pass as prose."""
    return marker.join(text.split())
