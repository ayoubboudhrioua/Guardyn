"""SENTINEL defense service.

POST /v1/decision  - the contract the simulator calls
GET  /v1/trace     - the decision trace the observability dashboard reads
GET  /healthz
"""

from __future__ import annotations

import os
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.decide import evaluate as legacy_evaluate
from app.flow.engine import evaluate as flow_evaluate
from app.models import DefenseDecision, DefenseRequest
from app.trace import read_all, record

MODE = os.environ.get("GUARDYN_MODE", "flow").lower()
evaluate = flow_evaluate if MODE == "flow" else legacy_evaluate
ABLATE = {s.strip() for s in os.environ.get("SENTINEL_ABLATE", "").split(",") if s.strip()}

# Debug aid: append every raw request to this file so tests can replay real traffic.
CAPTURE = os.environ.get("GUARDYN_CAPTURE", "")

app = FastAPI(title="SENTINEL defense", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "mode": MODE, "ablated": ",".join(sorted(ABLATE))}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    started = time.perf_counter()
    if CAPTURE:
        with open(CAPTURE, "a", encoding="utf-8") as fh:
            fh.write(request.model_dump_json() + "\n")
    decided, trace = evaluate(request)
    if ABLATE:
        decided, trace = _reapply_without(request, decided, trace)
    trace["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    trace["ablated"] = sorted(ABLATE)
    record(trace)
    return decided


def _reapply_without(request: DefenseRequest, decided: DefenseDecision, trace: dict):
    """Ablation harness: recompute the decision with named signals switched off."""
    from app.decide import apply_caps
    from app.fusion import band, confidence, fuse

    kept = {k: v for k, v in trace["signals"].items() if k not in ABLATE}
    risk = fuse(kept)
    risk = apply_caps(risk, trace.get("caps", {}))
    outcome = band(risk)
    codes = sorted(kept, key=lambda c: -kept[c])[:16] or ["USER_GOAL_ALIGNED"]
    trace = {**trace, "signals": kept, "risk": risk, "decision": outcome, "reason_codes": codes}
    return (
        DefenseDecision(
            decision=outcome,
            risk_score=risk,
            confidence=confidence(kept, risk),
            reason_codes=codes,
            explanation=f"ablation run; signals disabled: {','.join(sorted(ABLATE))}",
        ),
        trace,
    )


@app.get("/v1/trace")
def trace() -> JSONResponse:
    return JSONResponse(read_all())