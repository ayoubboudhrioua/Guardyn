"""Authority attribution: who is actually asking for this action?

Thesis: prompt injection is an authority-confusion bug, not a content bug.
Untrusted content may supply *data* to an action; it must never supply the
*authority* for one. So for each candidate action we ask two questions:

  mandate_support  - how well is this action explained by the user's own goal
                     and by content the agent legitimately trusts?
  directive_support - how well is it explained by a command found in untrusted
                     content?

Obeying an injection scores high on the second and low on the first. Faithfully
quoting attacker text into an internal note scores high on the first regardless
of what the text says, which is exactly the behaviour the challenge demands.
"""

from __future__ import annotations

import re

from app.models import CandidateAction, DefenseRequest
from app.canonical import closure, normalize, squash
from app.directives import Directive, extract

UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}
SENSITIVE = {"confidential", "restricted"}
_ID = re.compile(r"\b([A-Z]{2,6}-[A-Z0-9]{2,12})\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")


def split_by_trust(request: DefenseRequest) -> tuple[list[str], list[str], list[str]]:
    """(untrusted texts, trusted texts, sensitive texts) from the conversation."""
    prov = {r.id: r.provenance for r in request.provenance}
    untrusted: list[str] = []
    trusted: list[str] = []
    sensitive: list[str] = []
    for item in request.conversation:
        ps = [prov[p] for p in item.provenance_ids if p in prov]
        if any(p.trust_level in UNTRUSTED for p in ps):
            untrusted.append(item.content)
        else:
            trusted.append(item.content)
        if any(p.sensitivity in SENSITIVE for p in ps):
            sensitive.append(item.content)
    return untrusted, trusted, sensitive


CONTROL_MAX_CHARS = 80


def action_values(action: CandidateAction) -> list[str]:
    """Control-plane arguments only: the values that steer *which* action this is.

    A long free-text body is data the action carries, not a choice it encodes.
    Conflating the two is what makes naive taint tracking refuse to let an analyst
    quote a phishing mail into a case note - the text is attacker-written, but the
    decision to file it came from the user.
    """
    if action.type != "tool_call":
        return []
    return [
        str(v)
        for v in action.arguments.values()
        if v is not None and 3 <= len(str(v)) <= CONTROL_MAX_CHARS
    ]


def data_values(action: CandidateAction) -> list[str]:
    """Free-text the action carries. Governed by the sink check, not by authority."""
    out = [action.content] if action.content else []
    out += [str(v) for v in action.arguments.values() if v is not None and len(str(v)) > CONTROL_MAX_CHARS]
    return out


def _covered(value: str, haystacks: list[str]) -> bool:
    n = normalize(value)
    if len(n) < 3:
        return False
    return any(n in normalize(h) for h in haystacks)


def mandate_support(action: CandidateAction, goal: str, trusted: list[str]) -> float:
    """Fraction of this action's parameters the trusted context can account for."""
    values = action_values(action)
    if not values:
        return 1.0
    pool = [goal, *trusted]
    hits = sum(1 for v in values if _covered(v, pool))
    tool_hit = 1.0 if action.tool and re.search(rf"\b{re.escape(action.tool)}\b", goal, re.I) else 0.0
    base = hits / len(values)
    return min(1.0, 0.85 * base + 0.15 * tool_hit + (0.15 if base > 0 else 0.0))


def directive_support(action: CandidateAction, directives: list[Directive]) -> tuple[float, Directive | None]:
    """Strongest match between this action and any command found in untrusted text."""
    values = [normalize(v) for v in action_values(action) if len(normalize(v)) >= 3]
    best, best_d = 0.0, None
    for d in directives:
        score = 0.0
        if action.tool and action.tool.lower() in d.tools:
            score += 0.6
        blob = normalize(d.text)
        if values:
            matched = sum(1 for v in values if v in blob)
            score += 0.4 * (matched / len(values))
        if score > best:
            best, best_d = min(score, 1.0), d
    return best, best_d


def untrusted_only_parameters(
    action: CandidateAction, goal: str, trusted: list[str], untrusted: list[str]
) -> list[str]:
    """Parameters that exist nowhere except in untrusted content.

    These are the fingerprints of an injected plan: an account, a recipient or a
    query the user never mentioned and no trusted record contains.
    """
    out = []
    untrusted_closed = [closure(u) for u in untrusted]
    for v in action_values(action):
        if _covered(v, [goal, *trusted]):
            continue
        if _covered(v, untrusted_closed):
            out.append(v)
    return out


def analyse(request: DefenseRequest, action: CandidateAction) -> dict:
    untrusted, trusted, sensitive = split_by_trust(request)
    known = list(request.policy_context.get("allowed_tools", [])) + list(
        request.policy_context.get("consequential_tools", [])
    )
    directives: list[Directive] = []
    for text in untrusted:
        directives.extend(extract(text, known))

    mandate = mandate_support(action, request.user_goal, trusted)
    directed, source = directive_support(action, directives)
    orphans = untrusted_only_parameters(action, request.user_goal, trusted, untrusted)

    return {
        "mandate_support": round(mandate, 3),
        "directive_support": round(directed, 3),
        "directive_span": source.as_dict() if source else None,
        "directive_encoded": bool(source and source.encoded),
        "untrusted_only_parameters": orphans,
        "untrusted_texts": untrusted,
        "trusted_texts": trusted,
        "sensitive_texts": sensitive,
        "directive_count": len(directives),
    }
