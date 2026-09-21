"""Stage 1 - Guardyn labels: information-flow control over trust and sensitivity.

Two independent axes. Trust answers "may this speak with authority"; sensitivity
answers "where may this travel". A derived value inherits the *minimum* trust and
the *maximum* sensitivity of everything that fed it - the weakest link, never the
strongest. Memory freezes its label at write time, so recall never launders trust.
"""

from __future__ import annotations

from dataclasses import dataclass

TRUST_ORDER = [
    "adversary_controlled",
    "untrusted_external",
    "untrusted_internal",
    "trusted_internal",
    "authenticated_user",
    "system_policy",
]
SENSITIVITY_ORDER = ["public", "internal", "confidential", "restricted"]

AUTHORITATIVE = {"system_policy", "authenticated_user"}
UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}


def trust_rank(level: str) -> int:
    return TRUST_ORDER.index(level) if level in TRUST_ORDER else 0


def sensitivity_rank(level: str) -> int:
    return SENSITIVITY_ORDER.index(level) if level in SENSITIVITY_ORDER else 1


@dataclass(frozen=True)
class Label:
    trust: str = "system_policy"
    sensitivity: str = "public"

    def join(self, other: "Label") -> "Label":
        """Weakest trust, strongest sensitivity."""
        return Label(
            trust=min(self.trust, other.trust, key=trust_rank),
            sensitivity=max(self.sensitivity, other.sensitivity, key=sensitivity_rank),
        )

    @property
    def authoritative(self) -> bool:
        return self.trust in AUTHORITATIVE

    @property
    def untrusted(self) -> bool:
        return self.trust in UNTRUSTED

    def as_dict(self) -> dict[str, str]:
        return {"trust": self.trust, "sensitivity": self.sensitivity}


def join_all(labels: list[Label]) -> Label:
    if not labels:
        return Label()
    out = labels[0]
    for lab in labels[1:]:
        out = out.join(lab)
    return out


def may_flow(data: Label, sink: Label) -> bool:
    """Confidentiality rule: a value may only reach a sink cleared for it."""
    return sensitivity_rank(sink.sensitivity) >= sensitivity_rank(data.sensitivity)


def label_conversation(request) -> list[tuple[object, Label]]:
    """Attach a joined label to every conversation item."""
    prov = {r.id: r.provenance for r in request.provenance}
    out = []
    for item in request.conversation:
        parts = [
            Label(trust=prov[p].trust_level, sensitivity=prov[p].sensitivity)
            for p in item.provenance_ids
            if p in prov
        ]
        out.append((item, join_all(parts) if parts else Label(trust="trusted_internal", sensitivity="internal")))
    return out
