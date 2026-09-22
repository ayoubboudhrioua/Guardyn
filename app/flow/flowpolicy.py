"""L3 - flow policy: reading a record does not license disclosing everything in it.

Rule (FIDES / CaMeL style): a protected atom whose sensitivity is above a sink's ceiling may
reach that sink only through a resource/field/destination-scoped policy grant. The rule is
applied to every sink - the reply, internal records, memory and outbound tools - not only to
external ones. The previous Guardyn checked external sinks alone, which is how a restricted
service-account token could be read on request and then repeated in the reply.

Matching happens in canonical space (`normalize` strips spacing and punctuation, `closure`
adds base64/hex/url/rot13/reversed decodings), so no rule per obfuscation trick is needed.
A plain or spaced-out leak is redacted; an encoded one cannot be cleanly redacted and is
reported as such so the ladder can block it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.canonical import closure, normalize
from app.flow import ledger, policy
from app.labels import sensitivity_rank
from app.models import CandidateAction, DefenseRequest
from app.sinks import payload_text

PARTIAL_MIN = 10  # a leaked fragment this long (normalised) counts as a leak of the atom


@dataclass
class Finding:
    atom: ledger.Atom
    sink: str
    kind: str | None
    encoding: str  # "plain" | "partial" | "encoded"
    matched: str  # the normalised span that matched

    @property
    def redactable(self) -> bool:
        return self.encoding in ("plain", "partial")

    def as_dict(self) -> dict:
        return {"sink": self.sink, "kind": self.kind, "encoding": self.encoding, **self.atom.as_dict()}


def user_text(request: DefenseRequest) -> str:
    """Everything the authenticated user has said: the goal plus earlier user turns."""
    parts = [request.user_goal]
    parts += [c.content for c in request.conversation if c.role == "user"]
    return "\n".join(parts)


def _fragment(atom_norm: str, payload_norm: str) -> str | None:
    """Longest-enough slice of the atom that appears in the payload, if any."""
    if atom_norm in payload_norm:
        return atom_norm
    if len(atom_norm) < PARTIAL_MIN * 2:
        return None
    step = max(PARTIAL_MIN // 2, 1)
    for i in range(0, len(atom_norm) - PARTIAL_MIN + 1, step):
        probe = atom_norm[i : i + PARTIAL_MIN]
        if probe in payload_norm:
            return probe
    return None


def check(
    request: DefenseRequest,
    action: CandidateAction,
    atoms: list[ledger.Atom],
    pol: policy.PolicySet,
    text: str | None = None,
) -> list[Finding]:
    sink = policy.sink_of(pol, request, action)
    if sink is None or not atoms:
        return []
    raw = payload_text(action) if text is None else text
    if not raw:
        return []
    ceiling = pol.ceiling(sink)
    plain_norm = normalize(raw)
    closed_norm = normalize(closure(raw))

    out: list[Finding] = []
    for atom in atoms:
        if sensitivity_rank(atom.sensitivity) <= ceiling:
            continue
        n = normalize(atom.value)
        kind = pol.kind_of(atom.terms)
        if pol.permits_disclosure(atom, sink, action):
            continue
        frag = _fragment(n, plain_norm)
        if frag:
            out.append(Finding(atom, sink, kind, "plain" if frag == n else "partial", frag))
            continue
        frag = _fragment(n, closed_norm)
        if frag:
            out.append(Finding(atom, sink, kind, "encoded", frag))
    return out


def pattern(fragment: str) -> re.Pattern[str]:
    """Regex that finds `fragment` even with separators between its characters."""
    return re.compile(r"[^A-Za-z0-9]*".join(re.escape(c) for c in fragment), re.IGNORECASE)


def _scrub(text: str, findings: list[Finding]) -> str:
    for f in findings:
        text = pattern(f.matched).sub(f"[REDACTED:{f.kind or 'sensitive'}]", text)
    return text


def redact(action: CandidateAction, findings: list[Finding]) -> CandidateAction | None:
    """Same action with every redactable atom replaced. None if nothing was changed."""
    fixable = [f for f in findings if f.redactable]
    if not fixable:
        return None
    args = {k: _scrub(v, fixable) if isinstance(v, str) else v for k, v in action.arguments.items()}
    content = _scrub(action.content, fixable) if action.content else action.content
    if args == action.arguments and content == action.content:
        return None
    return CandidateAction(
        type=action.type, tool=action.tool, arguments=args, content=content, final=action.final
    )


def verified(
    request: DefenseRequest,
    rewritten: CandidateAction,
    atoms: list[ledger.Atom],
    pol: policy.PolicySet,
) -> bool:
    """A rewrite is only offered if re-checking it finds no residue."""
    return not check(request, rewritten, atoms, pol)
