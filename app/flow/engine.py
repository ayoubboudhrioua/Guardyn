"""Guardyn-Flow decision pipeline (L0 to L7). See docs/ARCHITECTURE.md.

The original Guardyn committee runs first and supplies the deterministic core: the plan contract
(L0), custody and passports, and the policy and lifecycle judges (L2). Flow adds the ledger and
flow policy (L1, L3), the two gated model layers (L4, L5), the flag registry (L6) and the ladder
(L7) on top of it.
"""

from __future__ import annotations

import json
import os
import time

from app import authority, suspicion
from app.canonical import normalize
from app.decide import CATEGORY, evaluate as legacy_evaluate, target_of
from app.flow import counterfactual, flowpolicy, judge, llm, policy
from app.flow import ledger as ledger_mod
from app.flow.flags import SINK_FLAG, Flag, from_legacy, signals as flag_signals
from app.flow.ladder import choose
from app.fusion import confidence, fuse
from app.models import DefenseDecision, DefenseRequest

# Ablation switch: GUARDYN_DISABLE=L3,L4,L5,BUDGET turns those layers off so each one's
# contribution can be measured on its own.
DISABLED = {p.strip().upper() for p in os.environ.get("GUARDYN_DISABLE", "").split(",") if p.strip()}

FLOW_CATEGORY = {
    "SENSITIVE_IN_REPLY": "Some details were left out because you did not ask for them.",
    "SENSITIVE_IN_RECORD": "Some details were left out because you did not ask for them.",
    "SENSITIVE_IN_MEMORY": "Some details were left out because you did not ask for them.",
    "SENSITIVE_TO_UNLICENSED_SINK": "That content cannot go to that destination.",
    "ENCODED_EXFIL": "That content cannot go to that destination.",
    "CALL_BUDGET_EXCEEDED": "That tool has been used enough for this task.",
    "COUNTERFACTUAL_DIVERGENCE": "That action needs a human to look at it.",
    "TASK_MISALIGNED": "That action needs a human to look at it.",
}


def _gate_llm(exposes: bool, facts: dict, legacy_risk: float) -> bool:
    """Model layers only run where they can change the outcome: an action that writes somewhere
    or is consequential, with untrusted directive-like content in play."""
    if "L4" in DISABLED or not (exposes and llm.available()):
        return False
    return bool(facts["untrusted_texts"]) and (facts["directive_count"] > 0 or legacy_risk >= 0.2)


def evaluate(request: DefenseRequest) -> tuple[DefenseDecision, dict]:
    started = time.perf_counter()
    legacy, trace = legacy_evaluate(request)
    candidate = request.candidate_action
    action = target_of(request)
    layers = ["L0", "L2", "L1", "L3"]

    pol = policy.select(request)
    atoms = ledger_mod.build(request)
    findings = [] if "L3" in DISABLED else flowpolicy.check(request, action, atoms, pol)

    flags: list[Flag] = from_legacy(trace["signals"])
    for f in findings:
        code = "ENCODED_EXFIL" if f.encoding == "encoded" else SINK_FLAG[f.sink]
        flags.append(Flag(code, 1.0, "L3", f.as_dict()))
    over = 0 if "BUDGET" in DISABLED else policy.call_budget_exceeded(pol, request, action)
    if over:
        flags.append(Flag("CALL_BUDGET_EXCEEDED", 0.6, "L2", {"tool": action.tool, "prior_calls": over}))

    sink = policy.sink_of(pol, request, action)
    consequential = trace["contract"] and action.tool in set(trace["contract"].get("consequential_tools", []))
    exposes = bool(sink) or bool(consequential)

    facts = authority.analyse(request, action)
    model_info: dict = {}
    if _gate_llm(exposes, facts, trace["risk"]):
        budget = llm.Budget()
        layers.append("L4")
        flag, info = judge.assess(request.user_goal, action, facts["untrusted_texts"], budget)
        model_info["judge"] = info
        if flag:
            flags.append(flag)
            if "L5" not in DISABLED:
                layers.append("L5")
                cf, cf_info = counterfactual.attribute(request, action, budget)
                model_info["counterfactual"] = cf_info
                if cf:
                    flags.append(cf)

    new_only = [f for f in flags if f.layer in ("L3", "L4", "L5") or f.code == "CALL_BUDGET_EXCEEDED"]
    risk = round(1.0 - (1.0 - trace["risk"]) * (1.0 - fuse(flag_signals(new_only))), 4)

    def recheck(rewritten):
        return flowpolicy.check(request, rewritten, atoms, pol)

    outcome = choose(
        legacy=legacy.decision,
        legacy_rewrite=legacy.rewritten_action,
        action=action,
        candidate=candidate,
        flags=flags,
        findings=findings,
        risk=risk,
        exposes=exposes,
        recheck=recheck,
    )
    layers = [x for x in layers if x not in DISABLED]

    if outcome.decision != legacy.decision or outcome.rewritten != legacy.rewritten_action:
        suspicion.update(request.run_id, 0, 0, False, intervened=outcome.decision != "allow")

    sig = flag_signals(flags)
    codes = sorted(sig, key=lambda c: -sig[c])[:16] or ["USER_GOAL_ALIGNED"]
    message = next(
        (FLOW_CATEGORY.get(c) or CATEGORY.get(c) for c in codes if c in FLOW_CATEGORY or c in CATEGORY),
        "That action was not permitted here.",
    )
    explanation = "Action is accounted for by your request." if outcome.decision == "allow" else message

    decision = DefenseDecision(
        decision=outcome.decision,
        risk_score=risk,
        confidence=confidence(sig, risk),
        reason_codes=codes,
        explanation=explanation[:500],
        rewritten_action=outcome.rewritten if outcome.decision == "rewrite" else None,
        metadata={
            "mode": "flow",
            "policy": pol.name,
            "layers": layers,
            "families": sorted({f.family for f in flags}),
            "ladder": outcome.reason,
        },
    )
    trace.update(
        {
            "mode": "flow",
            "decision": outcome.decision,
            "risk": risk,
            "reason_codes": codes,
            "policy": pol.name,
            "layers": layers,
            "flags": [f.as_dict() for f in flags],
            "atoms_tracked": len(atoms),
            "flow_findings": [f.as_dict() for f in findings],
            "model_layers": model_info,
            "ladder": {"reason": outcome.reason, "notes": outcome.notes},
            "legacy_decision": legacy.decision,
            "flow_latency_ms": round((time.perf_counter() - started) * 1000, 2),
        }
    )
    return decision, _scrub_trace(trace, atoms)


def _scrub_trace(trace: dict, atoms: list[ledger_mod.Atom]) -> dict:
    """The trace is a file on disk. It must not become a second place the secret leaks to."""
    if not atoms:
        return trace
    text = json.dumps(trace, default=str)
    for atom in atoms:
        text = flowpolicy.pattern(normalize(atom.value)).sub("[REDACTED]", text)
        text = text.replace(atom.value, "[REDACTED]")
    return json.loads(text)
