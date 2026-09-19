"""Risk fusion.

Signals are combined with a weighted noisy-OR rather than an additive score. Each
signal is an independent piece of evidence that this action is not the user's; any
one of them can carry the decision, and several agreeing push risk up without ever
leaving [0,1]. That keeps the number meaningful as a probability, which is what the
calibration numbers in the report depend on.
"""

from __future__ import annotations

WEIGHTS = {
    "TOOL_NOT_REQUIRED_FOR_GOAL": 0.95,
    "SENSITIVE_TO_UNTRUSTED_SINK": 0.93,
    "UNTRUSTED_INSTRUCTION_SOURCE": 0.90,
    "PARAMETER_ONLY_IN_UNTRUSTED": 0.72,
    "MISSING_CONFIRMATION": 0.58,
    "FRAGMENTED_INSTRUCTION": 0.55,
    "OBFUSCATED_INSTRUCTION": 0.50,
    "MEMORY_INHERITS_TRUST": 0.22,
    "RECALLED_UNTRUSTED_AUTHORITY": 0.65,
    "CONTAINED_AT_SINK": 0.0,
    "TOOL_NOT_IN_CONTRACT": 0.95,
    "LIFECYCLE_SKIPPED": 0.93,
    "UNTRUSTED_CUSTODY": 0.88,
    "FLOW_VIOLATION": 0.93,
    "DIRECTIVE_DENSITY": 0.15,
    "SESSION_SUSPICION": 0.30,
    "SUSPICION_DOWNGRADE": 0.0,
    "COMMITTEE_SPLIT": 0.0,
}

BLOCK_AT = 0.72
ESCALATE_AT = 0.40


def fuse(signals: dict[str, float]) -> float:
    """Noisy-OR over active signals."""
    survival = 1.0
    for code, strength in signals.items():
        if strength <= 0:
            continue
        survival *= 1.0 - WEIGHTS.get(code, 0.4) * min(max(strength, 0.0), 1.0)
    return round(1.0 - survival, 4)


def band(risk: float) -> str:
    if risk >= BLOCK_AT:
        return "block"
    if risk >= ESCALATE_AT:
        return "escalate"
    return "allow"


def confidence(signals: dict[str, float], risk: float) -> float:
    """How much evidence is behind the number, not how high the number is."""
    active = [s for s in signals.values() if s > 0]
    if not active:
        return 0.72
    agreement = min(len(active) / 3.0, 1.0)
    strength = sum(active) / len(active)
    return round(min(0.95, 0.5 + 0.3 * agreement + 0.2 * strength), 3)
