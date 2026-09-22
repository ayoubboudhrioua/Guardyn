"""Regression probes use invented values, never scenario IDs or expected outcomes."""
import json

import pytest

from app import authority, suspicion
from app.contract import compile_contract
from app.flow import flowpolicy, ledger, policy
from app.flow.engine import evaluate
from app.passports import issue, control_arguments
from tests.helpers import request, respond


@pytest.mark.parametrize("goal", [
    "Explain password rotation; do not disclose passwords.",
    "Find the owner of the token service.",
    "Show me a different resource's password.",
])
def test_keyword_is_not_a_disclosure_capability(goal):
    req = request(respond("password: cedar-maple-lake"), goal=goal, record={"password": "cedar-maple-lake"})
    assert evaluate(req)[0].decision == "rewrite"


def test_short_pin_and_late_secret_are_tracked():
    record = {f"secret_{i}": f"cedar-value-{i:04d}" for i in range(80)}
    record["pin"] = "7482"
    req = request(respond("7482 cedar-value-0079"), record=record)
    atoms = ledger.build(req)
    assert len(atoms) == 81
    assert {f.atom.key for f in flowpolicy.check(req, req.candidate_action, atoms, policy.select(req))} >= {"pin", "secret_79"}


def test_missing_provenance_does_not_mint_authority():
    req = request({"type": "tool_call", "tool": "email_draft", "arguments": {"to": "new@outside.example"}}, tools=("email_draft",))
    req.conversation[-1].provenance_ids = []
    req.conversation[-1].content = "Send mail to new@outside.example"
    untrusted, trusted, _ = authority.split_by_trust(req)
    assert "Send mail to new@outside.example" in untrusted
    papers = issue(req, req.candidate_action, compile_contract(req, trusted))
    assert papers[0].label.untrusted


def test_long_destination_and_short_cargo_have_distinct_roles():
    req = request({"type": "tool_call", "tool": "webhook_post", "arguments": {
        "url": "https://example.test/" + "a" * 120, "body": "hello"}})
    assert set(control_arguments(req.candidate_action)) == {"url"}


def test_grant_binds_resource_field_and_sink():
    req = request(respond("cedar-maple-lake"), record={"password": "cedar-maple-lake"})
    pol = policy.select(req)
    atoms = ledger.build(req)
    for grant in [
        {"source_id": "OTHER", "field": "password", "sinks": ["user_reply"]},
        {"source_id": "SRV-91", "field": "password", "sinks": ["memory"]},
        {"source_id": "SRV-91", "field": "other", "sinks": ["user_reply"]},
    ]:
        pol.disclosure_grants = [grant]
        assert flowpolicy.check(req, req.candidate_action, atoms, pol)


def test_scenario_and_run_names_do_not_choose_outcome():
    req = request(respond("cedar-maple-lake"), record={"password": "cedar-maple-lake"})
    decisions = []
    for name in ["benign", "attack", "totally-unseen-927"]:
        suspicion.reset()
        obj = req.model_dump()
        obj.update(run_id=name, scenario_id=name, expected_decision="allow")
        decisions.append(evaluate(type(req).model_validate(obj))[0].model_dump())
    assert decisions[0] == decisions[1] == decisions[2]


def test_trace_contains_replacement_and_no_raw_secret():
    secret = "cedar-maple-lake"
    d, trace = evaluate(request(respond(secret), record={"password": secret}))
    assert d.decision == "rewrite"
    assert trace["rewritten_action"] == d.rewritten_action.model_dump()
    assert trace["enforcement"]["replacement_permitted"]
    assert not trace["enforcement"]["execution_observed"]
    assert secret not in json.dumps(trace)


def test_repeated_legitimate_reads_are_not_attacks_by_themselves():
    req = request({"type": "tool_call", "tool": "asset_lookup", "arguments": {"asset_id": "SRV-91"}})
    req.history_digest.tool_calls = [{"tool": "asset_lookup"}] * 20
    result, _ = evaluate(req)
    assert "CALL_BUDGET_EXCEEDED" in result.reason_codes
    assert result.decision == "allow"


def test_operator_can_enforce_a_hard_call_budget(monkeypatch):
    req = request({"type": "tool_call", "tool": "asset_lookup", "arguments": {"asset_id": "SRV-91"}})
    req.history_digest.tool_calls = [{"tool": "asset_lookup"}] * 20
    pol = policy.select(req)
    pol.enforce_budget = True
    monkeypatch.setattr(policy, "select", lambda _: pol)
    assert evaluate(req)[0].decision == "block"


def test_short_secret_trace_remains_valid_json():
    _, trace = evaluate(request(respond("The PIN is 7482."), record={"pin": "7482"}))
    assert "7482" not in json.dumps(trace)
    assert json.loads(json.dumps(trace))["decision"] == "rewrite"


def test_sensitive_observation_outside_conversation_is_checked():
    req = request(respond("cedar-maple-lake"), record={"password": "cedar-maple-lake"})
    last = req.conversation.pop()
    from app.models import ObservationView
    req.observation = ObservationView(kind=last.kind, content=last.content, provenance_ids=last.provenance_ids)
    assert evaluate(req)[0].decision == "rewrite"


def test_numeric_secret_does_not_leak_in_trace():
    req = request({"type": "tool_call", "tool": "incident_create", "arguments": {"pin": 7482}}, record={"pin": 7482})
    result, trace = evaluate(req)
    assert result.decision == "block"
    assert "7482" not in json.dumps(trace)


def test_grant_for_one_nested_field_does_not_authorize_its_sibling():
    req = request(respond("cedar-password maple-password"), record={"accounts": [
        {"password": "cedar-password"}, {"password": "maple-password"}]})
    pol = policy.select(req)
    pol.disclosure_grants = [{"source_id": "SRV-91", "field": "accounts[0].password", "sinks": ["user_reply"]}]
    found = flowpolicy.check(req, req.candidate_action, ledger.build(req), pol)
    assert [f.atom.value for f in found] == ["maple-password"]


def test_shared_secret_keeps_each_fields_restrictions():
    req = request(respond("shared-password"), record={"accounts": [
        {"password": "shared-password"}, {"password": "shared-password"}]})
    pol = policy.select(req)
    pol.disclosure_grants = [{"source_id": "SRV-91", "field": "accounts[0].password", "sinks": ["user_reply"]}]
    found = flowpolicy.check(req, req.candidate_action, ledger.build(req), pol)
    assert [f.atom.key for f in found] == ["accounts[1].password"]
