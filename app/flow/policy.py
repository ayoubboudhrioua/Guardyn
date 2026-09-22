"""L2 - policy engine. Declarative policy sets, evaluated deterministically.

Policies live in `policies/*.yaml`: one base set plus one per domain, merged key by key with
the domain winning. They are data rather than code (Progent's argument) so a reviewer can read
exactly what is enforced and an ablation can swap one out.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from app.labels import sensitivity_rank
from app.models import CandidateAction, DefenseRequest

POLICY_DIR = Path(os.environ.get("GUARDYN_POLICY_DIR", Path(__file__).resolve().parents[2] / "policies"))

SINK_ORDER = ["user_reply", "internal_record", "memory", "external"]


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@lru_cache(maxsize=1)
def _load_all() -> tuple[dict, list[dict]]:
    base: dict = {}
    domains: list[dict] = []
    if not POLICY_DIR.exists():
        return base, domains
    for path in sorted(POLICY_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if path.stem == "base":
            base = data
        else:
            domains.append(data)
    return base, domains


@dataclass
class PolicySet:
    name: str = "none"
    sinks: dict[str, str] = field(default_factory=dict)
    tool_sinks: dict[str, str] = field(default_factory=dict)
    kinds: dict[str, dict] = field(default_factory=dict)
    max_calls_per_tool: int = 8
    disclosure_grants: list[dict] = field(default_factory=list)
    enforce_budget: bool = False

    def ceiling(self, sink: str) -> int:
        """Sensitivity rank that may reach `sink` unlicensed."""
        return sensitivity_rank(self.sinks.get(sink, "public"))

    def kind_of(self, key_terms: list[str]) -> str | None:
        for kind, spec in self.kinds.items():
            if any(t in spec.get("key_terms", []) for t in key_terms):
                return kind
        return None

    def permits_disclosure(self, atom, sink: str, action: CandidateAction) -> bool:
        """Only resource/field/sink-scoped grants from trusted policy declassify data."""
        for grant in self.disclosure_grants:
            if not isinstance(grant, dict):
                continue
            if grant.get("source_id") != atom.source_id or grant.get("field") != atom.key:
                continue
            if sink not in grant.get("sinks", []):
                continue
            if sink == "external":
                recipient = action.arguments.get("to") or action.arguments.get("url")
                if not recipient or grant.get("recipient") != recipient:
                    continue
            return True
        return False


def select(request: DefenseRequest) -> PolicySet:
    """Base policy overlaid with the domain policy that matches `policy_context.policy_id`."""
    base, domains = _load_all()
    merged = dict(base)
    policy_id = str(request.policy_context.get("policy_id", ""))
    for dom in domains:
        prefix = (dom.get("match") or {}).get("policy_id_prefix")
        if prefix and policy_id.startswith(prefix):
            merged = _merge(merged, {k: v for k, v in dom.items() if k != "match"})
            break
    return PolicySet(
        name=merged.get("name", "base"),
        sinks={**merged.get("sinks", {}), **request.policy_context.get("sinks", {})},
        tool_sinks={**merged.get("tool_sinks", {}), **request.policy_context.get("tool_sinks", {})},
        kinds=merged.get("disclosure_kinds", {}),
        max_calls_per_tool=int((merged.get("budgets") or {}).get("max_calls_per_tool", 8)),
        disclosure_grants=list(request.policy_context.get("disclosure_grants", [])),
        enforce_budget=bool((merged.get("budgets") or {}).get("enforce", False)),
    )


def sink_of(policy: PolicySet, request: DefenseRequest, action: CandidateAction) -> str | None:
    """Which sink this action writes to, or None if it only reads."""
    from app import sinks as legacy_sinks

    if action.type == "respond":
        return "user_reply"
    if action.type == "memory_write":
        return "memory"
    if action.type != "tool_call" or not action.tool:
        return None
    if action.tool in legacy_sinks.OUTBOUND:
        cls = legacy_sinks.classify(request, action)
        return "external" if cls == legacy_sinks.SINK_EXTERNAL else "internal_record"
    return policy.tool_sinks.get(action.tool)


def call_budget_exceeded(policy: PolicySet, request: DefenseRequest, action: CandidateAction) -> int:
    """Number of prior calls to this tool when it is over budget, else 0."""
    if action.type != "tool_call" or not action.tool:
        return 0
    prior = sum(1 for c in request.history_digest.tool_calls if c.get("tool") == action.tool)
    return prior if prior >= policy.max_calls_per_tool else 0
