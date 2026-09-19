"""Stage 0 - Mandate Compiler.

The task contract is compiled from SYSTEM_POLICY and AUTHENTICATED_USER only,
before a single untrusted byte is read. Untrusted content may narrow the contract;
it may never widen it. That single invariant kills false-approval and forged-closure
attacks structurally, with no content analysis at all: a document cannot grant a
capability the user never asked for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.canonical import normalize

_ID = re.compile(r"\b([A-Z]{2,6}-[A-Z0-9]{2,12})\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
_MONEY = re.compile(r"\b\d[\d,]{2,}(?:\.\d{2})?\b")


@dataclass
class Contract:
    allowed_tools: set[str] = field(default_factory=set)
    consequential_tools: set[str] = field(default_factory=set)
    confirmation_required: set[str] = field(default_factory=set)
    internal_domains: set[str] = field(default_factory=set)
    entities: set[str] = field(default_factory=set)
    goal: str = ""
    rules: list[dict] = field(default_factory=list)

    def licenses_tool(self, tool: str | None) -> bool:
        return tool is None or tool in self.allowed_tools

    def mentions(self, value: str) -> bool:
        n = normalize(value)
        return len(n) >= 3 and any(n in normalize(e) or normalize(e) in n for e in self.entities)

    def as_dict(self) -> dict:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "consequential_tools": sorted(self.consequential_tools),
            "entities": sorted(self.entities)[:24],
            "internal_domains": sorted(self.internal_domains),
        }


def compile_contract(request, trusted_texts: list[str]) -> Contract:
    """Build the contract from policy + user goal + trusted context only."""
    pc = request.policy_context or {}
    goal = request.user_goal or ""

    entities: set[str] = set()
    for text in [goal, *trusted_texts]:
        entities.update(_ID.findall(text))
        entities.update(_EMAIL.findall(text))
        entities.update(m.replace(",", "") for m in _MONEY.findall(text))
    entities.update(w for w in re.findall(r"[A-Za-z][\w'-]{3,}", goal))

    domains = {d.lower() for d in pc.get("internal_email_domains", [])}
    # Fall back to domains that appear in trusted context: an address the policy or
    # the directory already names is internal; one that only an attachment names is not.
    for text in [goal, *trusted_texts]:
        for addr in _EMAIL.findall(text):
            domains.add(addr.split("@", 1)[1].lower())

    return Contract(
        allowed_tools=set(pc.get("allowed_tools", [])),
        consequential_tools=set(pc.get("consequential_tools", [])),
        confirmation_required=set(pc.get("confirmation_required_tools", [])),
        internal_domains=domains,
        entities=entities,
        goal=goal,
        rules=list(pc.get("rules", [])),
    )
