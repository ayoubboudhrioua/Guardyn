"""Decision orchestration.

Order matters. The contract is compiled from trusted input before anything
untrusted is read (Stage 0). Labels and passports establish custody (Stage 1 and
idea A). Three judges vote (idea D). Fusion turns the signals into a calibrated
risk score, the suspicion dial decides how early the rewrite ladder engages
(idea C), and the result resolves to exactly one of the four allowed outcomes.
"""

from __future__ import annotations

import hashlib
import json

from app import assembler, authority, committee, lifecycle, memory_trust, passports, sinks, suspicion
from app.committee import ALLOW, BLOCK, ESCALATE, Verdict
from app.contract import compile_contract
from app.directives import extract as extract_directives
from app.fusion import band, confidence, fuse
from app.labels import Label, may_flow
from app.models import CandidateAction, DefenseDecision, DefenseRequest
from app.rewrite import safer

# The agent is told a category. The trace keeps the detail. An adversary that can
# watch the agent's public actions must not be able to use block messages as an oracle.
CATEGORY = {
    "TOOL_NOT_IN_CONTRACT": "That tool is not part of this task.",
    "LIFECYCLE_SKIPPED": "That step cannot run before its prerequisite.",
    "MISSING_CONFIRMATION": "That action needs human approval first.",
    "UNTRUSTED_CUSTODY": "That action is not supported by your request.",
    "FLOW_VIOLATION": "That content cannot go to that destination.",
    "COMMITTEE_SPLIT": "That action needs a human to look at it.",
}
STATUS_CONSEQUENTIAL = {"ticket_update": {"closed", "resolved"}, "incident_update": {"closed"}}


def action_digest(action: CandidateAction) -> str:
    def canon(v: object) -> object:
        if isinstance(v, str):
            return " ".join(v.split())
        if isinstance(v, float) and v.is_integer():
            return int(v)
        return v

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canon(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]


def target_of(request: DefenseRequest) -> CandidateAction:
    a = request.candidate_action
    return a.confirmation_for if a.type == "request_confirmation" and a.confirmation_for else a


def is_consequential(contract, action: CandidateAction) -> bool:
    if action.type != "tool_call" or action.tool is None:
        return False
    if action.tool in contract.consequential_tools or action.tool in contract.confirmation_required:
        return True
    status = action.arguments.get("status")
    return isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(action.tool, set())


# --------------------------------------------------------------------- judges


def judge_policy(request, action, contract) -> Verdict:
    v = Verdict("policy")
    if action.type == "tool_call" and not contract.licenses_tool(action.tool):
        v.signals["TOOL_NOT_IN_CONTRACT"] = 1.0
        v.evidence["tool"] = action.tool
        v.verdict = BLOCK
    available = contract.allowed_tools | contract.consequential_tools
    skipped = lifecycle.violation(action, request.history_digest, available)
    if skipped:
        v.signals["LIFECYCLE_SKIPPED"] = 1.0
        v.evidence["lifecycle"] = skipped
        v.verdict = BLOCK
    if is_consequential(contract, action) and request.candidate_action.type != "request_confirmation":
        if action_digest(action) not in request.history_digest.confirmations_granted:
            v.signals["MISSING_CONFIRMATION"] = 1.0
            v.verdict = max(v.verdict, ESCALATE, key=lambda x: committee.SEVERITY[x])
    v.note = "contract compiled from policy and user goal only"
    return v


def judge_custody(request, action, contract, facts, papers) -> Verdict:
    v = Verdict("custody")
    unexplained = max(0.0, 1.0 - facts["mandate_support"])

    bad = passports.untrusted_passports(papers)
    if bad and action.type == "tool_call":
        v.signals["UNTRUSTED_CUSTODY"] = min(1.0, len(bad) / 2.0)
        v.evidence["passports"] = [p.as_dict() for p in bad[:4]]
        v.verdict = BLOCK

    directed = facts["directive_support"] * unexplained
    if directed > 0.15:
        v.signals["UNTRUSTED_INSTRUCTION_SOURCE"] = min(1.0, directed * 1.4)
        v.evidence["directive"] = facts["directive_span"]
        if facts["directive_encoded"]:
            v.signals["OBFUSCATED_INSTRUCTION"] = 1.0
        v.verdict = BLOCK

    leak = facts["leak"]
    if leak["leak"]:
        v.signals["FLOW_VIOLATION"] = 1.0
        v.evidence["exfiltration"] = leak
        v.verdict = BLOCK

    if facts["fragmented"]:
        v.signals["FRAGMENTED_INSTRUCTION"] = facts["fragmented"]
        v.evidence["assembled_from"] = facts["fragment_span"]
        v.verdict = BLOCK

    if facts["recalled_authority"]:
        v.signals["RECALLED_UNTRUSTED_AUTHORITY"] = facts["recalled_authority"]
        v.verdict = BLOCK

    if memory_trust.memory_write_taint(action, facts["untrusted_texts"]):
        v.signals["MEMORY_INHERITS_TRUST"] = 1.0
        v.evidence["memory_taint"] = True
    v.note = "arguments traced to first appearance; memory frozen at write time"
    return v


def judge_content(request, action, facts, dial, consequential) -> Verdict:
    """Weakest judge by design. It may raise concern; it may not carry a decision
    on its own, and it never escalates a read - that is pure false-positive cost."""
    v = Verdict("content")
    if facts["directive_count"] >= 3:
        v.signals["DIRECTIVE_DENSITY"] = min(1.0, facts["directive_count"] / 6.0)
    if dial >= 0.65 and consequential and action_digest(action) not in request.history_digest.confirmations_granted:
        v.signals["SESSION_SUSPICION"] = dial
        v.verdict = ESCALATE
    v.note = f"suspicion dial {dial}"
    return v


# ------------------------------------------------------------------ pipeline


def evaluate(request: DefenseRequest) -> tuple[DefenseDecision, dict]:
    candidate = request.candidate_action
    action = target_of(request)

    facts = authority.analyse(request, action)
    confirmed = action_digest(action) in request.history_digest.confirmations_granted
    if confirmed:
        # A verified approval is authoritative for the exact action digest.
        # It does not declassify protected data or license tools outside policy.
        facts["mandate_support"] = 1.0
    contract = compile_contract(request, facts["trusted_texts"])
    known = sorted(contract.allowed_tools | contract.consequential_tools)
    untrusted = facts["untrusted_texts"]
    unexplained = max(0.0, 1.0 - facts["mandate_support"])

    fragments = assembler.assemble(untrusted, known, window=4)
    frag_strength, frag_span = authority.directive_support(action, fragments) if fragments else (0.0, None)
    facts["fragmented"] = min(1.0, frag_strength) if frag_strength * unexplained > 0.2 else 0.0
    facts["fragment_span"] = frag_span.as_dict() if frag_span else None

    recalled = memory_trust.recalled_untrusted(request)
    rec_strength = 0.0
    if recalled and action.type == "tool_call":
        rec_strength, _ = authority.directive_support(
            action, [d for t in recalled for d in extract_directives(t, known)]
        )
    facts["recalled_authority"] = min(1.0, rec_strength) if rec_strength * unexplained > 0.25 else 0.0
    facts["leak"] = sinks.exfiltration(request, action, facts["sensitive_texts"])

    papers = passports.issue(request, action, contract)
    dial = suspicion.read(request.run_id)

    consequential = is_consequential(contract, action)
    verdicts = [
        judge_policy(request, action, contract),
        judge_custody(request, action, contract, facts, papers),
        judge_content(request, action, facts, dial, consequential),
    ]
    signals: dict[str, float] = {}
    evidence: dict = {}
    for v in verdicts:
        signals.update(v.signals)
        evidence.update(v.evidence)

    risk = fuse(signals)
    injected = max(
        signals.get("UNTRUSTED_INSTRUCTION_SOURCE", 0.0),
        signals.get("FRAGMENTED_INSTRUCTION", 0.0),
        signals.get("RECALLED_UNTRUSTED_AUTHORITY", 0.0),
        signals.get("UNTRUSTED_CUSTODY", 0.0),
    )

    contained = (
        action.type == "tool_call"
        and action.tool in contract.allowed_tools
        and not consequential
        and verdicts[0].verdict == ALLOW
        and facts["leak"]["sink"] in (sinks.SINK_INTERNAL, sinks.SINK_USER)
        and not facts["leak"]["leak"]
    )
    caps = {
        "contained": bool(contained),
        "respond": action.type == "respond",
        "memory_write": action.type == "memory_write" and not facts["leak"]["leak"],
        "confirmation_discount": candidate.type == "request_confirmation" and injected < 0.3,
    }
    risk = apply_caps(risk, caps)
    if caps["contained"] and risk <= 0.33:
        signals.setdefault("CONTAINED_AT_SINK", 1.0)
        for v in verdicts:
            if v.judge != "content":
                v.verdict = ALLOW

    outcome, split = committee.combine(verdicts, risk)
    if band(risk) == ALLOW and outcome == ALLOW:
        outcome = ALLOW
    elif band(risk) == BLOCK and outcome != BLOCK and injected >= 0.3:
        outcome = BLOCK
    if split and outcome == ALLOW:
        signals["COMMITTEE_SPLIT"] = 0.4

    rewritten = None
    if outcome in (BLOCK, ESCALATE) and injected < 0.3:
        alt = safer(action, sorted(contract.allowed_tools))
        if alt is not None:
            outcome, rewritten = "rewrite", alt
    if outcome == ALLOW and dial >= 0.7 and consequential and not confirmed:
        alt = safer(action, sorted(contract.allowed_tools))
        if alt is not None:
            outcome, rewritten = "rewrite", alt
            signals["SUSPICION_DOWNGRADE"] = dial

    suspicion.update(
        request.run_id,
        directives_seen=facts["directive_count"],
        untrusted_params=len(passports.untrusted_passports(papers)),
        clean=outcome == ALLOW and not signals,
        intervened=outcome != ALLOW,
    )

    codes = sorted(signals, key=lambda c: -signals[c])[:16] or ["USER_GOAL_ALIGNED"]
    agent_message = next((CATEGORY[c] for c in codes if c in CATEGORY), "That action was not permitted here.")

    trace = {
        "run_id": request.run_id,
        "step_id": request.step_id,
        "action": action.model_dump(),
        "decision": outcome,
        "risk": risk,
        "reason_codes": codes,
        "signals": signals,
        "evidence": evidence,
        "mandate_support": facts["mandate_support"],
        "directive_support": facts["directive_support"],
        "passports": [p.as_dict() for p in papers],
        "committee": [v.as_dict() for v in verdicts],
        "committee_split": split,
        "suspicion": dial,
        "contract": contract.as_dict(),
        "caps": caps,
    }
    decision = DefenseDecision(
        decision=outcome,
        risk_score=risk,
        confidence=confidence(signals, risk),
        reason_codes=codes,
        explanation=(agent_message if outcome != ALLOW else "Action is accounted for by your request.")[:500],
        rewritten_action=rewritten,
        metadata={"suspicion": dial, "committee_split": split},
    )
    return decision, trace


def apply_caps(risk: float, caps: dict) -> float:
    if caps.get("confirmation_discount"):
        risk = round(risk * 0.45, 4)
    if caps.get("respond"):
        risk = min(risk, 0.3)
    if caps.get("memory_write"):
        risk = min(risk, 0.25)
    if caps.get("contained") and risk >= 0.34:
        risk = min(risk, 0.33)
    return risk
