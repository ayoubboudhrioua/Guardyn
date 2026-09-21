"""L7 - enforcement ladder: the least destructive action that removes the harm.

    allow -> redact -> downgrade -> escalate -> block

Redaction comes first because it is the only rung that stops a leak *and* lets the task finish.
Blocking a reply because it repeated a token discards the whole answer; redacting the token
keeps everything the user actually asked for. Every redaction is re-checked before it is
offered: if the rewritten action still leaks, the ladder skips to block.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.flow import flowpolicy
from app.flow.flags import FLOW, SEMANTIC, Flag, families
from app.fusion import BLOCK_AT, ESCALATE_AT
from app.models import CandidateAction


@dataclass
class Outcome:
    decision: str  # allow | rewrite | escalate | block
    rewritten: CandidateAction | None = None
    reason: str = ""
    notes: list[str] = field(default_factory=list)


def choose(
    *,
    legacy: str,
    legacy_rewrite: CandidateAction | None,
    action: CandidateAction,
    candidate: CandidateAction,
    flags: list[Flag],
    findings: list[flowpolicy.Finding],
    risk: float,
    exposes: bool,
    recheck,
) -> Outcome:
    """`exposes` is true when the action writes to a sink or is consequential.
    `recheck(action)` returns the leftover findings for a rewritten action."""
    notes: list[str] = []

    # 1. The old committee already blocked: nothing on this ladder is gentler than that.
    if legacy == "block":
        return Outcome("block", reason="policy", notes=["legacy committee blocked"])

    # 2. Protected data is heading somewhere it may not go.
    if findings:
        if candidate.type == "request_confirmation":
            return Outcome("block", reason="flow", notes=["unlicensed data inside a confirmation request"])
        if any(not f.redactable for f in findings):
            return Outcome("block", reason="flow", notes=["encoded disclosure cannot be redacted"])
        base = legacy_rewrite or action
        fixed = flowpolicy.redact(base, findings)
        if fixed is not None and not recheck(fixed):
            return Outcome("rewrite", rewritten=fixed, reason="redact", notes=["redacted and re-verified"])
        return Outcome("block", reason="flow", notes=["redaction could not be verified"])

    # 3. The old committee's verdicts stand when the flow layers found nothing to add.
    if legacy in ("rewrite", "escalate"):
        return Outcome(legacy, rewritten=legacy_rewrite, reason="policy")

    # 4. Independent families agreeing is the only route to a block from new evidence.
    fam = families(flags)
    if len(fam - {SEMANTIC}) >= 2 and risk >= BLOCK_AT:
        return Outcome("block", reason="agreement", notes=[f"families: {sorted(fam)}"])

    # 5. Weak or model-based evidence can only send a consequential action to a human.
    if exposes and risk >= ESCALATE_AT and fam <= {SEMANTIC, "authority"}:
        return Outcome("escalate", reason="weak-evidence")

    return Outcome("allow", notes=notes)


def has_flow(flags: list[Flag]) -> bool:
    return any(f.family == FLOW for f in flags)
