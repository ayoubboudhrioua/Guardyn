"""Safe substitutions.

A rewrite is preferable to a block whenever a lower-authority version of the same
action still serves the user's goal: drafting instead of sending, preparing instead
of executing. Rewrites are only offered for actions the user's own goal supports -
never to salvage an action that came from untrusted content.
"""

from __future__ import annotations

from app.models import CandidateAction

DOWNGRADE = {
    "email_send": "email_draft",
    "payment_execute": "payment_prepare",
    "remediation_execute": "remediation_prepare",
}


def safer(action: CandidateAction, allowed: list[str]) -> CandidateAction | None:
    if action.type != "tool_call" or action.tool is None:
        return None
    target = DOWNGRADE.get(action.tool)
    if not target or target not in allowed:
        return None
    return CandidateAction(type="tool_call", tool=target, arguments=dict(action.arguments))
