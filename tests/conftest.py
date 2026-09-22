import os
import pytest

# Unit tests never reach for a model unless they stub one in explicitly.
os.environ.setdefault("GUARDYN_LLM", "off")


@pytest.fixture(autouse=True)
def isolate_decision_state(tmp_path, monkeypatch):
    from app import suspicion, trace
    suspicion.reset()
    monkeypatch.setattr(trace, "TRACE_PATH", tmp_path / "decisions.jsonl")
    yield
    suspicion.reset()
