"""Where an action's payload ends up, and whether sensitive material may go there.

The exfiltration question is not 'does this text look like a secret' but
'is material the agent only learned from a confidential source now heading to a
destination that is less trusted than that source'. Comparing in the canonical
closure is what catches base64, hex, spacing and reversal without a rule per trick.
"""

from __future__ import annotations

from app.models import CandidateAction, DefenseRequest
from app.canonical import closure, normalize, opaque_tokens

OUTBOUND = {"email_send", "email_draft", "message_send", "webhook_post"}
SINK_USER, SINK_INTERNAL, SINK_MEMORY, SINK_EXTERNAL = "user", "internal", "memory", "external"
MIN_OVERLAP = 24


def classify(request: DefenseRequest, action: CandidateAction) -> str:
    if action.type == "respond":
        return SINK_USER
    if action.type == "memory_write":
        return SINK_MEMORY
    if action.tool in OUTBOUND:
        recipient = str(action.arguments.get("to", "")).lower()
        internal = [d.lower() for d in request.policy_context.get("internal_email_domains", [])]
        if recipient and not any(recipient.endswith("@" + d) for d in internal):
            return SINK_EXTERNAL
    return SINK_INTERNAL


def payload_text(action: CandidateAction) -> str:
    parts = [action.content or ""]
    parts += [str(v) for v in action.arguments.values() if v is not None]
    if action.confirmation_for is not None:
        parts.append(payload_text(action.confirmation_for))
    return "\n".join(p for p in parts if p)


def _shared_span(payload_norm: str, source: str, minimum: int = MIN_OVERLAP) -> str | None:
    src = normalize(source)
    if len(src) < minimum:
        return src if src and src in payload_norm else None
    step = max(minimum // 2, 1)
    for i in range(0, len(src) - minimum + 1, step):
        probe = src[i : i + minimum]
        if probe in payload_norm:
            return probe
    return None


def exfiltration(request: DefenseRequest, action: CandidateAction, sensitive: list[str]) -> dict:
    """Sensitive-source material crossing into a sink that should not receive it."""
    sink = classify(request, action)
    raw = payload_text(action)
    result = {"sink": sink, "leak": False, "encoding": None, "opaque_tokens": []}
    if sink in (SINK_USER, SINK_INTERNAL) or not raw:
        if sink == SINK_MEMORY:
            pass
        else:
            return result
    if not sensitive:
        return result

    for encoding, decoded in (("plain", raw), ("closure", closure(raw))):
        payload_norm = normalize(decoded)
        if not payload_norm:
            continue
        for source in sensitive:
            if _shared_span(payload_norm, source):
                result["leak"] = sink == SINK_EXTERNAL
                result["encoding"] = encoding
                result["opaque_tokens"] = opaque_tokens(raw)[:4]
                return result
    return result
