"""Cross-observation fragment assembly.

A multi-step attack splits one instruction over several records so that no single
observation contains anything actionable. Reassembling untrusted spans in the order
the agent saw them and re-parsing the concatenation restores the instruction, which
is the only place it was ever visible.
"""

from __future__ import annotations

from app.directives import Directive, extract


def assemble(untrusted: list[str], known_tools: list[str], window: int = 4) -> list[Directive]:
    """Directives visible only once adjacent untrusted spans are joined."""
    if len(untrusted) < 2:
        return []
    singles = {d.text for text in untrusted for d in extract(text, known_tools)}
    out: list[Directive] = []
    for size in range(2, min(window, len(untrusted)) + 1):
        for start in range(len(untrusted) - size + 1):
            joined = " ".join(untrusted[start : start + size])
            for d in extract(joined, known_tools):
                if d.text not in singles:
                    out.append(d)
    return out
