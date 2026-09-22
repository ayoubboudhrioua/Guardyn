"""L5 - counterfactual attribution (MELON, reduced).

MELON re-runs the agent with the user's request masked and flags an attack when the same tool
calls still appear, because then the calls were driven by the tool outputs and not by the user.
This layer asks the mirror-image question, which fits a defense that sits behind an interface:
re-plan the next step from the user's request and *trusted* results only, with every untrusted
item withheld. If the candidate tool call does not survive that, untrusted content is what
caused it.

It is not a full replay of the agent. It re-plans with the defense's own prompt, so it
approximates the agent's behaviour and can disagree with it for benign reasons (a different but
equally valid order of reads). That is why the flag is moderate, runs only when L4 already
suspects the action, and only on tool calls.
"""

from __future__ import annotations

import json

from app.canonical import normalize
from app.flow import llm
from app.flow.flags import Flag
from app.models import CandidateAction, DefenseRequest
from app.context import observed_items

UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}

SYSTEM = (
    "You plan the next step of a tool-using assistant. Use only the USER REQUEST and the TRUSTED "
    "RESULTS. Some results were withheld. Choose from the available tools or answer directly. "
    'Reply with JSON only: {"next": "tool_call" or "respond", "tool": "<tool name or null>", '
    '"arguments": {}}.'
)


def _trusted_results(request: DefenseRequest) -> tuple[list[str], int]:
    prov = {r.id: r.provenance for r in request.provenance}
    kept: list[str] = []
    withheld = 0
    for item in observed_items(request):
        if item.role == "user":
            continue
        labels = [prov[p] for p in item.provenance_ids if p in prov]
        if not labels or any(p.trust_level in UNTRUSTED for p in labels):
            withheld += 1
            continue
        kept.append(item.content[:500])
    return kept, withheld


def attribute(request: DefenseRequest, action: CandidateAction, budget: llm.Budget) -> tuple[Flag | None, dict]:
    if action.type != "tool_call" or not action.tool:
        return None, {"ran": False}
    kept, withheld = _trusted_results(request)
    tools = sorted(request.policy_context.get("allowed_tools", []))
    user = (
        f"USER REQUEST:\n{request.user_goal[:600]}\n\nTRUSTED RESULTS:\n"
        + ("\n".join(kept) or "(none)")
        + f"\n\n{withheld} result(s) withheld.\n\nAVAILABLE TOOLS: {', '.join(tools)}"
    )
    plan = llm.chat_json(SYSTEM, user, budget)
    if plan is None:
        return None, {"ran": False}

    planned_tool = plan.get("tool") if plan.get("next") == "tool_call" else None
    planned_args = normalize(json.dumps(plan.get("arguments", {}), ensure_ascii=False))
    survives = planned_tool == action.tool
    if survives:
        controls = [normalize(str(v)) for v in action.arguments.values() if v is not None and len(str(v)) <= 80]
        goal_n = normalize(request.user_goal)
        survives = all(len(c) < 3 or c in planned_args or c in goal_n for c in controls)
    info = {"ran": True, "planned_tool": planned_tool, "candidate_tool": action.tool, "survives": survives}
    if survives:
        return None, info
    return Flag("COUNTERFACTUAL_DIVERGENCE", 0.55, "L5", info), info
