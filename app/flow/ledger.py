"""L1 - flow ledger: which protected values has the agent seen, and how sensitive are they?

Following FIDES, every value carries a confidentiality label from where it was read. We only
track *protected atoms*: values that are credential-shaped, either because the field they sit
under is named like a secret or because the value itself is a high-entropy token. Ordinary
fields of a restricted record (an owner name, a criticality) are not atoms; blocking a reply for
repeating those would make the defense useless.

The ledger is rebuilt from the request each time. The simulator sends the whole conversation
with its provenance on every call, so no per-run state is needed and every decision is
replayable from a single request.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from app.canonical import normalize, opaque_tokens
from app.labels import sensitivity_rank, trust_rank
from app.models import DefenseRequest

# Field names that mark a value as credential-shaped. Split on _ - and camelCase before matching.
SECRET_KEY_WORDS = {
    "token", "secret", "password", "passwd", "passphrase", "credential", "credentials", "apikey",
    "key", "otp", "pin", "cookie", "session", "ssn", "iban", "pan", "cvv", "auth", "bearer",
}
MIN_ATOM_CHARS = 6
MAX_ATOMS = 64


def key_terms(key: str) -> list[str]:
    """`service_account_token` and `serviceAccountToken` both give [service, account, token]."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


@dataclass(frozen=True)
class Atom:
    value: str
    key: str
    kind: str  # "secret_field" | "opaque_token"
    sensitivity: str
    trust: str
    source_id: str
    origin: str  # the tool that returned it

    @property
    def terms(self) -> list[str]:
        return key_terms(self.key)

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "kind": self.kind,
            "sensitivity": self.sensitivity,
            "trust": self.trust,
            "origin": self.origin,
            "preview": self.value[:4] + "…" if len(self.value) > 4 else "…",
        }


def _walk(obj: object, path: str = ""):
    """Yield (leaf key, leaf value) pairs from parsed JSON."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, path)
    elif obj is not None and not isinstance(obj, bool):
        yield path, str(obj)


def _is_secret_key(key: str) -> bool:
    return any(t in SECRET_KEY_WORDS for t in key_terms(key))


def _extract(content: str) -> list[tuple[str, str, str]]:
    """(key, value, kind) candidates inside one item's text."""
    out: list[tuple[str, str, str]] = []
    try:
        parsed = json.loads(content)
    except (ValueError, TypeError):
        parsed = None
    seen: set[str] = set()
    if parsed is not None:
        for key, value in _walk(parsed):
            if len(value) < MIN_ATOM_CHARS or value in seen:
                continue
            if _is_secret_key(key):
                out.append((key, value, "secret_field"))
                seen.add(value)
            else:
                for tok in opaque_tokens(value):
                    if tok not in seen:
                        out.append((key or "value", tok, "opaque_token"))
                        seen.add(tok)
    else:
        for tok in opaque_tokens(content):
            if tok not in seen:
                out.append(("value", tok, "opaque_token"))
                seen.add(tok)
    return out


def build(request: DefenseRequest, floor: str = "confidential") -> list[Atom]:
    """Protected atoms from every conversation item labelled at or above `floor`."""
    prov = {r.id: r.provenance for r in request.provenance}
    minimum = sensitivity_rank(floor)
    atoms: list[Atom] = []
    seen: set[str] = set()
    for item in request.conversation:
        labels = [prov[p] for p in item.provenance_ids if p in prov]
        if not labels or item.role == "user":
            continue
        top = max(labels, key=lambda p: sensitivity_rank(p.sensitivity))
        if sensitivity_rank(top.sensitivity) < minimum:
            continue
        # An item's least-trusted provenance is its integrity label.
        low = min(labels, key=lambda p: trust_rank(p.trust_level))
        for key, value, kind in _extract(item.content):
            n = normalize(value)
            if len(n) < MIN_ATOM_CHARS or n in seen:
                continue
            seen.add(n)
            atoms.append(Atom(value, key, kind, top.sensitivity, low.trust_level, top.source_id, top.retrieved_via))
            if len(atoms) >= MAX_ATOMS:
                return atoms
    return atoms


__all__ = ["Atom", "build", "key_terms"]
