"""Creative idea C - the suspicion dial.

A session-level score that rises when the agent reads directive-looking text from a
low-trust source, and decays after clean steps. As it rises, the rewrite ladder
engages earlier: send becomes draft, execute becomes prepare. This is what gives the
defense a memory across a long-horizon attack whose individual steps all look benign.

State is keyed by run_id and lives only in this process. It is observability and
policy state, never authority: a high dial can tighten a decision, never loosen one.
"""

from __future__ import annotations

import threading

_LOCK = threading.Lock()
_DIAL: dict[str, float] = {}

# The dial keys on custody failures and interventions, not on how bossy the prose
# sounds. Ordinary vendor email is full of imperatives ("please pay by the 30th");
# treating that as evidence escalates benign work and buys nothing.
RISE_PER_INTERVENTION = 0.25
RISE_PER_UNTRUSTED_PARAM = 0.15
RISE_PER_EXCESS_DIRECTIVE = 0.05
DECAY_PER_CLEAN_STEP = 0.12
CEILING = 1.0


def read(run_id: str) -> float:
    with _LOCK:
        return round(_DIAL.get(run_id, 0.0), 3)


def update(run_id: str, directives_seen: int, untrusted_params: int, clean: bool, intervened: bool = False) -> float:
    with _LOCK:
        value = _DIAL.get(run_id, 0.0)
        if intervened:
            value += RISE_PER_INTERVENTION
        value += RISE_PER_UNTRUSTED_PARAM * min(untrusted_params, 2)
        value += RISE_PER_EXCESS_DIRECTIVE * max(0, min(directives_seen, 5) - 2)
        if clean:
            value -= DECAY_PER_CLEAN_STEP
        value = max(0.0, min(CEILING, value))
        _DIAL[run_id] = value
        return round(value, 3)


def reset(run_id: str | None = None) -> None:
    with _LOCK:
        if run_id is None:
            _DIAL.clear()
        else:
            _DIAL.pop(run_id, None)
