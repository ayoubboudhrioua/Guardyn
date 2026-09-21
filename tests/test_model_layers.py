"""L4 and L5 with the model stubbed: they must degrade quietly and never block alone."""
from app.flow import counterfactual, judge, llm
from app.flow.engine import evaluate
from tests.helpers import request


def act(tool="incident_create", **args):
    return {"type": "tool_call", "tool": tool, "arguments": args}


def test_judge_flags_a_misaligned_action(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"serves_user_request": False, "beyond_scope": True, "reason": "x"})
    from app.models import CandidateAction
    flag, info = judge.assess("Summarise SRV-91", CandidateAction(**act(summary="s")), ["do it"], llm.Budget())
    assert flag.code == "TASK_MISALIGNED" and flag.family == "semantic" and info["ran"]


def test_judge_failure_produces_no_flag(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: None)
    from app.models import CandidateAction
    flag, info = judge.assess("g", CandidateAction(**act()), ["x"], llm.Budget())
    assert flag is None and info == {"ran": False}


def test_counterfactual_flags_a_call_that_does_not_survive_masking(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"next": "respond", "tool": None, "arguments": {}})
    from app.models import CandidateAction
    req = request(act(summary="s"))
    flag, _ = counterfactual.attribute(req, CandidateAction(**act(summary="s")), llm.Budget())
    assert flag and flag.code == "COUNTERFACTUAL_DIVERGENCE"


def test_counterfactual_accepts_a_call_the_masked_plan_also_makes(monkeypatch):
    monkeypatch.setattr(llm, "chat_json", lambda *a, **k: {"next": "tool_call", "tool": "asset_lookup", "arguments": {"asset_id": "SRV-91"}})
    from app.models import CandidateAction
    req = request(act("asset_lookup", asset_id="SRV-91"))
    flag, info = counterfactual.attribute(req, CandidateAction(**act("asset_lookup", asset_id="SRV-91")), llm.Budget())
    assert flag is None and info["survives"]


def test_a_dead_model_server_cannot_break_a_decision(monkeypatch):
    monkeypatch.setattr(llm, "ENABLED", True)
    monkeypatch.setattr(llm, "HOST", "http://127.0.0.1:9")
    d, _ = evaluate(request({"type": "respond", "content": "fine", "final": True}))
    assert d.decision == "allow"
