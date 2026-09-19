"""Creative idea A - value passports: argument-level provenance.

Every value in a candidate action is traced back to where it *first appeared*. A
recipient that only ever showed up inside a vendor attachment has an untrusted
passport, no matter how the surrounding sentence is worded. This survives
paraphrase, because it never reads the attack - it reads the origin of the value.

It also reads well in a trace:
    recipient <- first seen in vendor_attachment (untrusted_external)
"""

from __future__ import annotations

from dataclasses import dataclass

from app.canonical import closure, normalize
from app.labels import Label, label_conversation

CONTROL_MAX_CHARS = 80


@dataclass
class Passport:
    name: str
    value: str
    label: Label
    source_kind: str
    first_seen: str
    found: bool

    def as_dict(self) -> dict:
        return {
            "argument": self.name,
            "value": self.value[:80],
            "first_seen": self.first_seen,
            "source_kind": self.source_kind,
            "trust": self.label.trust,
        }


def control_arguments(action) -> dict[str, str]:
    """Values that steer *which* action this is, as opposed to cargo it carries.

    A long free-text body is data. Conflating the two is what makes naive taint
    tracking refuse to let an analyst quote a phishing mail into a case note.
    """
    if action.type != "tool_call":
        return {}
    return {
        k: str(v)
        for k, v in action.arguments.items()
        if v is not None and 3 <= len(str(v)) <= CONTROL_MAX_CHARS
    }


def issue(request, action, contract) -> list[Passport]:
    labelled = label_conversation(request)
    goal_norm = normalize(contract.goal)
    out: list[Passport] = []

    for name, value in control_arguments(action).items():
        needle = normalize(value)
        if len(needle) < 3:
            continue
        if needle in goal_norm:
            out.append(Passport(name, value, Label(trust="authenticated_user"), "user_goal", "user goal", True))
            continue
        hit = None
        for item, label in labelled:
            if needle in normalize(item.content) or needle in normalize(closure(item.content)):
                hit = (item, label)
                break
        if hit is None:
            out.append(Passport(name, value, Label(trust="trusted_internal"), "agent", "not observed", False))
        else:
            item, label = hit
            out.append(Passport(name, value, label, item.kind or item.role, f"{item.role}/{item.kind}", True))
    return out


def worst(passports: list[Passport]) -> Label:
    labels = [p.label for p in passports]
    if not labels:
        return Label(trust="authenticated_user")
    out = labels[0]
    for lab in labels[1:]:
        out = out.join(lab)
    return out


def untrusted_passports(passports: list[Passport]) -> list[Passport]:
    return [p for p in passports if p.label.untrusted]
