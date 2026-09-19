"""Directive extraction: find attempts to *command* the agent inside observed content.

Important: finding a directive is not by itself grounds to block. Legitimate work
often requires reading, quoting, and even storing attacker text (see the
'quote the scam message verbatim' case). A directive only matters when the agent's
candidate action turns out to be *caused* by it. That comparison lives in authority.py.
"""

from __future__ import annotations

import re

from app.canonical import closure, squash

# "call <tool> with {...}" is the canonical shape, but we do not rely on it alone.
_CALL = re.compile(r"\b(?:call|invoke|run|execute|use)\s+([a-z][a-z0-9_]{2,63})\b", re.I)
_JSONISH = re.compile(r"\{[^{}]{0,400}\}")
_IMPERATIVE_LEAD = re.compile(
    r"(?m)^\s*(?:please\s+)?(?:now\s+)?(?:you\s+must\s+|you\s+should\s+)?"
    r"(call|invoke|run|execute|send|forward|email|draft|reply|paste|include|attach|"
    r"disable|close|approve|confirm|transfer|pay|remember|store|ignore|disregard|override)\b",
    re.I,
)


class Directive:
    """One attempted command, with the text span it came from."""

    __slots__ = ("text", "tools", "values", "encoded")

    def __init__(self, text: str, tools: list[str], values: list[str], encoded: bool) -> None:
        self.text = text[:400]
        self.tools = tools
        self.values = values
        self.encoded = encoded

    def as_dict(self) -> dict:
        return {"span": self.text[:200], "tools": self.tools, "encoded": self.encoded}


def _values_in(blob: str) -> list[str]:
    """Literal values a directive is trying to supply as arguments."""
    out: list[str] = []
    for chunk in _JSONISH.findall(blob):
        out.extend(re.findall(r'"([^"]{2,120})"', chunk))
    out.extend(re.findall(r"\b([A-Z]{2,6}-[A-Z0-9]{2,12})\b", blob))
    out.extend(re.findall(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b", blob))
    return [v for v in out if len(v) >= 3]


def extract(text: str, known_tools: list[str]) -> list[Directive]:
    """Directives found anywhere in the canonical closure of `text`."""
    found: list[Directive] = []
    plain_norm = squash(text)
    for segment in closure(text).split("\n"):
        if not segment.strip():
            continue
        encoded = squash(segment) not in plain_norm
        tools = {m.group(1).lower() for m in _CALL.finditer(segment)}
        tools |= {t for t in known_tools if re.search(rf"\b{re.escape(t)}\b", segment, re.I)}
        imperative = bool(_IMPERATIVE_LEAD.search(segment)) or bool(_CALL.search(segment))
        if not tools and not imperative:
            continue
        found.append(Directive(segment, sorted(tools), _values_in(segment), encoded))
    return found
