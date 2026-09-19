"""Memory inherits trust.

A memory entry written after reading untrusted content stays untrusted when it is
recalled. We never block the write outright - the newsletter task legitimately asks
the agent to remember something - we mark it, and we refuse to let a recalled entry
act as the authority for a later action.
"""

from __future__ import annotations

from app.models import CandidateAction, DefenseRequest
from app.canonical import normalize

MIN_OVERLAP = 24


def derived_from_untrusted(content: str, untrusted: list[str]) -> bool:
    body = normalize(content or "")
    if len(body) < 12:
        return False
    for source in untrusted:
        src = normalize(source)
        if len(src) < MIN_OVERLAP:
            continue
        step = max(MIN_OVERLAP // 2, 1)
        for i in range(0, len(body) - MIN_OVERLAP + 1, step):
            if body[i : i + MIN_OVERLAP] in src:
                return True
    return False


def recalled_untrusted(request: DefenseRequest) -> list[str]:
    """Conversation items recalled from memory that were tainted at write time."""
    prov = {r.id: r.provenance for r in request.provenance}
    out = []
    for item in request.conversation:
        if item.role != "memory" and item.kind not in ("memory", "memory_read"):
            continue
        ps = [prov[p] for p in item.provenance_ids if p in prov]
        if any(p.trust_level != "authenticated_user" for p in ps) or not ps:
            out.append(item.content)
    return out


def memory_write_taint(action: CandidateAction, untrusted: list[str]) -> bool:
    return action.type == "memory_write" and derived_from_untrusted(action.content or "", untrusted)
