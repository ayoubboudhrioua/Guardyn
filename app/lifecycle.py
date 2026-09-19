"""Least privilege - lifecycles as state machines.

prepare -> confirm -> execute cannot skip steps, and a sentence in an email saying
an officer already approved is not a confirmation. Only a confirmation recorded in
the agent's own history counts, because only that one has an authenticated origin.
"""

from __future__ import annotations

CHAINS = {
    "payment": ["payment_prepare", "payment_confirm", "payment_execute"],
    "remediation": ["remediation_prepare", "remediation_confirm", "remediation_execute"],
    "transfer": ["transfer_prepare", "transfer_confirm", "transfer_execute"],
}


def stage_of(tool: str | None) -> tuple[str, int] | None:
    for chain, steps in CHAINS.items():
        if tool in steps:
            return chain, steps.index(tool)
    return None


def violation(action, history_digest, available: set[str] | None = None) -> str | None:
    """Return a reason if this action skips a required predecessor.

    The chain is narrowed to the stages that actually exist in this domain. A
    domain with prepare and execute but no separate confirm tool routes approval
    through request_confirmation instead, and demanding a confirm tool that was
    never defined would downgrade legitimate, already-approved work.
    """
    if action.type != "tool_call":
        return None
    located = stage_of(action.tool)
    if located is None:
        return None
    chain, _ = located
    steps = CHAINS[chain]
    if available is not None:
        steps = [t for t in steps if t in available or t == action.tool]
    if action.tool not in steps:
        return None
    index = steps.index(action.tool)
    if index == 0:
        return None
    seen = {call.get("tool") for call in (history_digest.tool_calls or [])}
    required = steps[index - 1]
    if required not in seen:
        return f"{action.tool} requires {required} first; it was never executed in this run"
    return None
