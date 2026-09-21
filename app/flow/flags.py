"""L6 - typed flags. Every layer reports through the same shape.

A flag says what was seen (`code`), which question it answers (`family`), how strong it is
(`severity`, 0..1), which layer raised it and the evidence behind it. Families are what the
ladder reasons about: two *independent* families agreeing is far stronger evidence than one
family repeated.

  authority  - who is really asking for this action?
  flow       - where is protected data going?
  policy     - what do the task and policy permit?
  semantic   - weak, model-based or statistical hints. They never block on their own.
"""

from __future__ import annotations

from dataclasses import dataclass, field

AUTHORITY, FLOW, POLICY, SEMANTIC = "authority", "flow", "policy", "semantic"

FAMILY = {
    # authority
    "UNTRUSTED_CUSTODY": AUTHORITY,
    "UNTRUSTED_INSTRUCTION_SOURCE": AUTHORITY,
    "FRAGMENTED_INSTRUCTION": AUTHORITY,
    "RECALLED_UNTRUSTED_AUTHORITY": AUTHORITY,
    "OBFUSCATED_INSTRUCTION": AUTHORITY,
    "COUNTERFACTUAL_DIVERGENCE": AUTHORITY,
    "MEMORY_INHERITS_TRUST": AUTHORITY,
    # flow
    "SENSITIVE_TO_UNLICENSED_SINK": FLOW,
    "SENSITIVE_IN_REPLY": FLOW,
    "SENSITIVE_IN_RECORD": FLOW,
    "SENSITIVE_IN_MEMORY": FLOW,
    "ENCODED_EXFIL": FLOW,
    "FLOW_VIOLATION": FLOW,
    # policy
    "TOOL_NOT_IN_CONTRACT": POLICY,
    "LIFECYCLE_SKIPPED": POLICY,
    "MISSING_CONFIRMATION": POLICY,
    "CALL_BUDGET_EXCEEDED": POLICY,
    # semantic
    "TASK_MISALIGNED": SEMANTIC,
    "DIRECTIVE_DENSITY": SEMANTIC,
    "SESSION_SUSPICION": SEMANTIC,
}

SINK_FLAG = {
    "user_reply": "SENSITIVE_IN_REPLY",
    "internal_record": "SENSITIVE_IN_RECORD",
    "memory": "SENSITIVE_IN_MEMORY",
    "external": "SENSITIVE_TO_UNLICENSED_SINK",
}


@dataclass
class Flag:
    code: str
    severity: float
    layer: str
    evidence: dict = field(default_factory=dict)

    @property
    def family(self) -> str:
        return FAMILY.get(self.code, SEMANTIC)

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "family": self.family,
            "severity": round(self.severity, 3),
            "layer": self.layer,
            "evidence": self.evidence,
        }


def from_legacy(signals: dict[str, float]) -> list[Flag]:
    """The original Isnad committee's signals, re-labelled with a family."""
    layer_of = {"policy": {"TOOL_NOT_IN_CONTRACT", "LIFECYCLE_SKIPPED", "MISSING_CONFIRMATION"}}
    out = []
    for code, strength in signals.items():
        if strength <= 0 or code in ("CONTAINED_AT_SINK", "COMMITTEE_SPLIT", "SUSPICION_DOWNGRADE"):
            continue
        layer = "L2" if code in layer_of["policy"] else "L0-custody"
        out.append(Flag(code, float(strength), layer))
    return out


def families(flags: list[Flag], minimum: float = 0.3) -> set[str]:
    return {f.family for f in flags if f.severity >= minimum}


def signals(flags: list[Flag]) -> dict[str, float]:
    """Strongest severity per code, in the shape `fusion.fuse` expects."""
    out: dict[str, float] = {}
    for f in flags:
        out[f.code] = max(out.get(f.code, 0.0), f.severity)
    return out
