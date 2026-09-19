from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def body(**kw):
    out = {
        "run_id": "e2e", "step_id": 1, "user_goal": "Summarize ticket TCK-501.",
        "candidate_action": {"type": "tool_call", "tool": "ticket_read", "arguments": {"ticket_id": "TCK-501"}},
        "policy_context": {"allowed_tools": ["ticket_read"], "consequential_tools": ["email_send"]},
    }
    out.update(kw)
    return out


def test_healthz():
    assert client.get("/healthz").json()["status"] == "ok"


def test_allows_goal_aligned_action():
    assert client.post("/v1/decision", json=body()).json()["decision"] == "allow"


def test_blocks_tool_outside_contract():
    r = client.post("/v1/decision", json=body(
        candidate_action={"type": "tool_call", "tool": "email_send", "arguments": {"to": "a@b.example"}})).json()
    assert r["decision"] in ("block", "rewrite")


def test_block_message_is_category_level_not_an_oracle():
    r = client.post("/v1/decision", json=body(
        candidate_action={"type": "tool_call", "tool": "email_send", "arguments": {"to": "a@b.example"}})).json()
    # Detail belongs in the trace, not in a message the adversary can read back.
    assert "email_send" not in r["explanation"]
    assert r["reason_codes"]


def test_decision_is_one_of_four():
    r = client.post("/v1/decision", json=body()).json()
    assert r["decision"] in {"allow", "block", "escalate", "rewrite"}
    assert 0.0 <= r["risk_score"] <= 1.0
