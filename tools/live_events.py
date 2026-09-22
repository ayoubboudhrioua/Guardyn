"""Canonical live-dashboard evidence: scrubbing, event normalization and one-sentence captions.

Everything here is a projection of recorded evidence. Nothing in this module is read by the
defense, and scenario identifiers never influence a decision: they only label artifacts.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import UTC, datetime
from typing import Any

SCHEMA = "guardyn.live/1"
MAX_TEXT = 600

# The kit's canary generator produces exactly these shapes (sentinel/core/canary.py). Matching the
# shapes as well as the seeded values keeps a value we were not told about from reaching the browser.
GENERIC_PROTECTED = re.compile(
    r"SENTINEL_SECRET_[0-9A-F]{16}|SYNTN\d{18}|sntl_tok_[A-Za-z0-9]{24}|CTR-SYN-[0-9A-F]{10}"
)
PROTECTED_PREFIXES = ("SENTINEL_SECRET_", "SYNTN", "sntl_tok_", "CTR-SYN-")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
FRAGMENT = 8


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class Scrubber:
    """Replace seeded protected values, their common encodings and fragments with labels."""

    def __init__(self, protected: dict[str, str] | None = None) -> None:
        self._needles: list[tuple[str, str]] = []
        self._fragments: list[tuple[str, str]] = []
        for name, value in (protected or {}).items():
            if not value:
                continue
            label = f"[protected:{name}]"
            raw = value.encode()
            variants = {
                value,
                value[::-1],
                base64.b64encode(raw).decode().rstrip("="),
                base64.urlsafe_b64encode(raw).decode().rstrip("="),
                binascii.hexlify(raw).decode(),
                binascii.hexlify(raw).decode().upper(),
            }
            self._needles += [(v, label) for v in variants if v]
            core = value
            for prefix in PROTECTED_PREFIXES:
                if value.startswith(prefix):
                    core = value[len(prefix):]
            fragment_label = f"[protected:{name}:fragment]"
            for i in range(0, max(len(core) - FRAGMENT + 1, 0)):
                self._fragments.append((core[i:i + FRAGMENT], fragment_label))
        # Longest first, so a full value is labelled before any of its fragments.
        self._needles.sort(key=lambda item: -len(item[0]))

    def text(self, value: str, limit: int | None = MAX_TEXT) -> str:
        value = CONTROL.sub("", value)
        for needle, label in self._needles:
            if needle in value:
                value = value.replace(needle, label)
        value = GENERIC_PROTECTED.sub("[protected]", value)
        for needle, label in self._fragments:
            if needle in value:
                value = value.replace(needle, label)
        if limit is not None and len(value) > limit:
            value = value[:limit] + f"… [{len(value) - limit} more characters not shown]"
        return value

    def value(self, obj: Any, limit: int | None = MAX_TEXT) -> Any:
        if isinstance(obj, str):
            return self.text(obj, limit)
        if isinstance(obj, dict):
            return {self.text(str(k), 120): self.value(v, limit) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.value(v, limit) for v in obj[:200]]
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            scrubbed = self.text(str(obj), None)
            return obj if scrubbed == str(obj) else scrubbed
        return obj


def _action(scrub: Scrubber, action: dict | None) -> dict | None:
    if not action:
        return None
    return {
        "type": action.get("type"),
        "tool": action.get("tool"),
        "arguments": scrub.value(action.get("arguments") or {}),
        "content": scrub.text(action["content"]) if action.get("content") else None,
        "final": bool(action.get("final")),
        "confirmation_for": _action(scrub, action.get("confirmation_for")),
    }


def normalize_kit_event(event: dict, protection: str, scrub: Scrubber,
                        provenance: dict[str, dict] | None = None) -> tuple[str, dict] | None:
    """Map one official simulator event to a canonical (type, payload). Only observed fields."""
    kind, payload = event["type"], event.get("payload") or {}
    refs = list(event.get("provenance_refs") or [])
    sources = [provenance[r] for r in refs if provenance and r in provenance]
    if kind == "user_message":
        return "goal", {"turn": payload.get("turn"), "text": scrub.text(payload.get("text", ""))}
    if kind == "memory_read":
        return "source", {"kind": "memory", "entries": scrub.value(payload.get("entries", [])),
                          "provenance": sources, "provenance_refs": refs}
    if kind == "defense_decision":
        action = _action(scrub, payload.get("action"))
        if protection == "off":
            # The kit's allow-all control records "allow"; no defense examined the action.
            return "guard_not_applied", {"action": action, "note": "Protection off: baseline control run"}
        return "decision", {
            "decision": payload.get("decision"),
            "action": action,
            "reason_codes": list(payload.get("reason_codes") or [])[:16],
            "explanation": scrub.text(payload.get("explanation") or "", 300) or None,
            "risk_score": payload.get("risk_score"),
            "confidence": payload.get("confidence"),
            "rewritten_action": _action(scrub, payload.get("rewritten_action")),
            "defense_error": payload.get("defense_error"),
        }
    if kind == "human_confirmation":
        return "approval", {"tool": payload.get("tool"), "approved": payload.get("approved")}
    if kind == "tool_request":
        return "tool_request", {"tool": payload.get("tool"), "arguments": scrub.value(payload.get("arguments") or {}),
                                "confirmed": payload.get("confirmed")}
    if kind in ("tool_result", "retrieval_result"):
        result = payload.get("result")
        excerpt = scrub.text(result if isinstance(result, str) else json.dumps(result, default=str)) if result is not None else None
        return "tool_result", {"tool": payload.get("tool"), "succeeded": payload.get("succeeded"),
                               "error": scrub.text(payload["error"], 300) if payload.get("error") else None,
                               "effects": scrub.value(payload.get("effects") or []),
                               "retrieval": kind == "retrieval_result", "excerpt": excerpt,
                               "provenance": sources, "provenance_refs": refs}
    if kind == "model_output":
        if "malformed_action" in payload:
            return "model_error", {"message": scrub.text(payload["malformed_action"], 300), "recoverable": True}
        return "response", {"content": scrub.text(payload.get("content") or ""), "final": payload.get("final")}
    if kind == "memory_write":
        return "memory_write", scrub.value({k: v for k, v in payload.items()})
    if kind == "policy_violation":
        return "finding", scrub.value({k: payload.get(k) for k in ("rule_id", "severity", "message", "kind")})
    if kind in ("task_success", "task_failure"):
        return "evaluation_end", {"task_success": kind == "task_success",
                                  "summary": scrub.text(payload.get("summary", ""), 200),
                                  "termination": scrub.text(str(payload.get("termination", "")), 200)}
    return None


def outcome_assessment(outcome: dict, scrub: Scrubber, protection: str) -> dict:
    """The official scorer's outcome, kept as separate fields. Unknown stays None, never False."""
    decisions = outcome.get("decisions") or []
    counts = {d: sum(1 for x in decisions if x.get("decision") == d) for d in ("allow", "block", "escalate", "rewrite")}
    return {
        "protection": protection,
        "attack_present": outcome.get("attack_present"),
        "attack_success": outcome.get("attack_success") if outcome.get("attack_present") else None,
        "task_success": outcome.get("task_success"),
        "critical_violation": outcome.get("critical_violation"),
        "data_flow_violation": outcome.get("data_flow_violation"),
        "termination": scrub.text(str(outcome.get("termination")), 200),
        "steps": outcome.get("steps"),
        # A baseline has no defense verdicts: the kit's allow-all control is not a decision maker.
        "counts": counts if protection == "on" else None,
        "defense_errors": sum(1 for x in decisions if x.get("defense_error")) if protection == "on" else None,
        "graders": [{"condition": scrub.text(str(g.get("condition")), 200), "passed": g.get("passed")}
                    for g in outcome.get("grader_results") or []],
        "findings": [scrub.value({k: f.get(k) for k in ("rule_id", "severity", "message")})
                     for f in outcome.get("findings") or []],
    }


# ---- one-sentence captions ---------------------------------------------------------------------

REASON_TEXT = {
    "authority": "it follows an instruction from an untrusted source, outside the task's mandate",
    "flow": "it would send protected data to a destination the task does not license",
    "redact": "it contained protected values the task did not ask for",
    "budget": "the active policy's call budget for this tool was exhausted",
    "agreement": "independent checks agreed the action is not supported by the task",
    "weak-evidence": "the evidence against it is weak, so a human should decide",
}
CODE_TEXT = {
    "TOOL_NOT_IN_CONTRACT": "the tool is not part of this task",
    "MISSING_CONFIRMATION": "this consequential action requires confirmation",
    "LIFECYCLE_SKIPPED": "a required earlier step was not executed",
    "UNTRUSTED_INSTRUCTION_SOURCE": "it follows an instruction from untrusted content",
    "FLOW_VIOLATION": "protected data would reach a disallowed destination",
    "SENSITIVE_IN_REPLY": "the reply contained a protected value",
    "SENSITIVE_IN_RECORD": "the record contained a protected value",
    "ENCODED_EXFIL": "it carries an encoded protected value",
    "CALL_BUDGET_EXCEEDED": "the tool's call budget was exhausted",
}
VERB = {"block": "blocked", "rewrite": "rewrote", "escalate": "escalated", "allow": "allowed"}


def _subject(action: dict | None) -> str:
    if not action:
        return "this action"
    if action.get("type") == "respond":
        return "this reply"
    if action.get("type") == "memory_write":
        return "this memory write"
    if action.get("type") == "request_confirmation":
        return "this confirmation request"
    return f"this {action.get('tool') or 'tool'} call"


def _because(defense_row: dict | None, decision: dict) -> str | None:
    row = defense_row or {}
    reason = (row.get("ladder") or {}).get("reason")
    if reason in REASON_TEXT and not (reason == "policy"):
        return REASON_TEXT[reason]
    for code in decision.get("reason_codes") or []:
        if code in CODE_TEXT:
            return CODE_TEXT[code]
    return None


def explain_step(step_events: list[dict], defense_row: dict | None, run_state: str) -> str:
    """One factual sentence about the decision at a step, built from recorded fields only."""
    finished = run_state in ("completed", "failed", "cancelled", "interrupted")
    by_type: dict[str, list[dict]] = {}
    for e in step_events:
        by_type.setdefault(e["type"], []).append(e)
    requests = by_type.get("tool_request", [])
    results = by_type.get("tool_result", [])
    responses = by_type.get("response", [])
    if "guard_not_applied" in by_type:
        action = by_type["guard_not_applied"][-1]["payload"].get("action")
        if results:
            ok = results[-1]["payload"].get("succeeded")
            return (f"Protection was off for this baseline run; {_subject(action)} went straight to the sandbox "
                    f"and the tool {'reported success' if ok else 'reported failure'}.")
        if responses:
            return f"Protection was off for this baseline run; {_subject(action)} was emitted to the user unchecked."
        return f"Protection was off for this baseline run; no execution has been observed yet for {_subject(action)}."
    if "decision" not in by_type:
        if "model_error" in by_type:
            return "The model produced output that was not a valid action; no candidate action exists for this step."
        if "candidate" in by_type:
            return "A candidate action was proposed; no defense decision has been recorded for it yet."
        return "No decision has been recorded for this step."
    decision = by_type["decision"][-1]["payload"]
    verdict, action = decision.get("decision"), decision.get("action")
    if decision.get("defense_error"):
        return (f"The defense returned an error ({decision['defense_error']}); the kit applied its fail mode "
                f"and recorded {verdict}, which is not a Guardyn judgement.")
    because = _because(defense_row, decision)
    head = f"Guardyn {VERB.get(verdict, verdict)} {_subject(action)}"
    head += f" because {because}" if because and verdict != "allow" else ""
    if verdict == "allow":
        if results:
            ok = results[-1]["payload"].get("succeeded")
            return f"{head} as supported by the task; the tool then {'reported success' if ok else 'reported failure'}."
        if responses:
            return f"{head} as supported by the task; the reply was emitted."
        return f"{head}; allow is permission only, and no execution has been observed yet."
    if verdict == "block":
        if requests:
            return f"{head}, yet a tool request was still observed for this step; enforcement is not confirmed."
        tail = ("no tool request or reply was observed for this step." if finished
                else "withholding is not yet verified while the run is still active.")
        return f"{head}; {tail}"
    if verdict == "rewrite":
        replacement = decision.get("rewritten_action")
        checks = (defense_row or {}).get("enforcement") or {}
        check = "the replacement passed Guardyn's re-check" if checks.get("replacement_permitted") else \
            "no replacement re-check was recorded"
        if not replacement:
            return f"{head} but supplied no replacement, so the action was withheld."
        if requests or responses:
            return f"{head}; {check}, and the replacement was executed."
        tail = "the replacement was not executed." if finished else "execution is not yet verified."
        return f"{head}; {check}, and {tail}"
    if verdict == "escalate":
        approvals = by_type.get("approval", [])
        if approvals:
            approved = approvals[-1]["payload"].get("approved")
            return (f"{head}: approval was required, and the simulated reviewer "
                    f"{'approved' if approved else 'declined'} it.")
        return f"{head}: approval is required for this action; no approval has been observed."
    return f"{head}."
