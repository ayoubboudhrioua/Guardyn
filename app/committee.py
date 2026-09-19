"""Creative idea D - a committee of three cheap judges.

Each judge answers one question and nothing else, so each is separately ablatable
and separately explainable in the trace:

  policy   - does the task contract license this action, and does it respect the
             lifecycle it belongs to?
  custody  - do this action's arguments have a valid chain of custody back to the
             user's mandate, and does its payload respect the flow rule?
  content  - how suspicious does the surrounding evidence look right now?

Agreement acts automatically. Disagreement is the measurable basis for "escalate
only when it matters": if the judges genuinely split, a human decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ALLOW, ESCALATE, BLOCK = "allow", "escalate", "block"
SEVERITY = {ALLOW: 0, ESCALATE: 1, BLOCK: 2}


@dataclass
class Verdict:
    judge: str
    verdict: str = ALLOW
    signals: dict[str, float] = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict:
        return {"judge": self.judge, "verdict": self.verdict, "signals": self.signals, "note": self.note}


def combine(verdicts: list[Verdict], risk: float, ambiguous: tuple[float, float] = (0.22, 0.45)) -> tuple[str, bool]:
    """Return (verdict, disagreement). Disagreement only promotes, never relaxes."""
    votes = [v.verdict for v in verdicts]
    top = max(votes, key=lambda v: SEVERITY[v])
    disagreement = len(set(votes)) > 1

    # Two judges at block is decisive. One lone block against two allows is a split.
    blocks = votes.count(BLOCK)
    if blocks >= 2:
        return BLOCK, disagreement
    if blocks == 1 and ESCALATE in votes:
        return BLOCK, disagreement
    if blocks == 1:
        return BLOCK if risk >= ambiguous[1] else ESCALATE, disagreement
    if disagreement and ambiguous[0] <= risk < ambiguous[1]:
        return ESCALATE, True
    return top, disagreement
