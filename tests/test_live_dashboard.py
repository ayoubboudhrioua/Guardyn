import base64
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from tools.live_dashboard import Busy, Orchestrator, create_app, read_events
from tools.live_events import Scrubber, explain_step, normalize_kit_event, outcome_assessment

SECRET = "SENTINEL_SECRET_069FB0E523FF6F99"
CATALOG = [{"id": "finance_false_approval", "split": "public", "domain": "finance", "title": "t", "description": "",
            "tags": [], "attack_present": True, "attack_family": "x", "max_steps": 25, "seed": 1, "featured": True}]


def ev(seq, type_, step=None, **payload):
    return {"seq": seq, "type": type_, "step": step, "payload": payload}


# ---- scrubbing ---------------------------------------------------------------------------------

def test_scrubber_removes_values_encodings_fragments_and_unknown_canary_shapes():
    s = Scrubber({"token": SECRET})
    text = " | ".join([SECRET, base64.b64encode(SECRET.encode()).decode(), SECRET.encode().hex(), SECRET[::-1],
                       "part " + SECRET[-10:], "sntl_tok_" + "a" * 24, "ordinary ACC-1001"])
    out = s.text(text, None)
    assert "069FB0E5" not in out and "23FF6F99" not in out and "aaaaaaaa" not in out
    assert "[protected:token]" in out and "[protected:token:fragment]" in out and "[protected]" in out
    assert "ordinary ACC-1001" in out
    assert s.value({"amount": 1250, "nested": [SECRET]}) == {"amount": 1250, "nested": ["[protected:token]"]}


def test_normalized_events_and_assessment_carry_no_protected_values():
    s = Scrubber({"token": SECRET})
    raw = {"type": "tool_result", "actor": "tool_gateway", "provenance_refs": [],
           "payload": {"tool": "ticket_read", "succeeded": True, "result": {"body": f"key={SECRET}"}, "effects": []}}
    kind, payload = normalize_kit_event(raw, "on", s)
    assert kind == "tool_result" and SECRET not in json.dumps(payload)
    outcome = {"attack_present": True, "attack_success": False, "task_success": True, "termination": "completed",
               "decisions": [{"decision": "block"}], "grader_results": [{"condition": f"reply omits {SECRET}", "passed": True}],
               "findings": []}
    assert SECRET not in json.dumps(outcome_assessment(outcome, s, "on"))


# ---- baseline honesty ----------------------------------------------------------------------------

def test_baseline_allow_all_is_reported_as_protection_off_not_a_verdict():
    raw = {"type": "defense_decision", "actor": "defense", "provenance_refs": [],
           "payload": {"action": {"type": "tool_call", "tool": "payment_confirm", "arguments": {}}, "decision": "allow",
                       "reason_codes": ["ALLOW_ALL"]}}
    kind, payload = normalize_kit_event(raw, "off", Scrubber())
    assert kind == "guard_not_applied" and "decision" not in payload
    assessment = outcome_assessment({"attack_present": True, "decisions": [{"decision": "allow"}]}, Scrubber(), "off")
    assert assessment["counts"] is None and assessment["defense_errors"] is None


def test_benign_attack_outcome_is_not_applicable_rather_than_false():
    assert outcome_assessment({"attack_present": False, "attack_success": False}, Scrubber(), "on")["attack_success"] is None


# ---- one-sentence explanations: grounded, never ahead of the evidence -------------------------------

def decision(verdict, tool="email_send", **extra):
    return ev(2, "decision", 1, decision=verdict, action={"type": "tool_call", "tool": tool}, reason_codes=extra.pop("codes", []),
              rewritten_action=extra.pop("rewritten", None), defense_error=extra.pop("error", None))


def test_block_is_not_claimed_as_enforced_until_the_run_ends_without_execution():
    events = [decision("block", codes=["TOOL_NOT_IN_CONTRACT"])]
    assert "not yet verified" in explain_step(events, None, "running")
    done = explain_step(events, None, "completed")
    assert "the tool is not part of this task" in done and "no tool request or reply was observed" in done
    leaked = explain_step(events + [ev(3, "tool_request", 1, tool="email_send")], None, "completed")
    assert "enforcement is not confirmed" in leaked


def test_allow_is_permission_not_success_and_escalate_is_not_approval():
    assert "permission only" in explain_step([decision("allow")], None, "running")
    ok = explain_step([decision("allow"), ev(3, "tool_result", 1, tool="email_send", succeeded=False)], None, "completed")
    assert "reported failure" in ok
    assert "no approval has been observed" in explain_step([decision("escalate")], None, "completed")
    approved = explain_step([decision("escalate"), ev(3, "approval", 1, approved=True)], None, "completed")
    assert "approved" in approved


def test_rewrite_separates_replacement_check_from_execution():
    events = [decision("rewrite", rewritten={"type": "tool_call", "tool": "email_send"})]
    row = {"ladder": {"reason": "redact"}, "enforcement": {"replacement_permitted": True}}
    pending = explain_step(events, row, "running")
    assert "passed Guardyn's re-check" in pending and "not yet verified" in pending
    executed = explain_step(events + [ev(3, "tool_request", 1)], row, "completed")
    assert "replacement was executed" in executed


def test_errors_and_baseline_are_never_described_as_guardyn_judgements():
    assert "not a Guardyn judgement" in explain_step([decision("block", error="TimeoutError")], None, "completed")
    base = explain_step([ev(1, "guard_not_applied", 1, action={"type": "tool_call", "tool": "payment_confirm"}),
                         ev(2, "tool_result", 1, succeeded=True)], None, "completed")
    assert base.startswith("Protection was off") and "Guardyn" not in base
    assert "no candidate action" in explain_step([ev(1, "model_error", 1, message="bad json")], None, "running")


# ---- orchestrator ------------------------------------------------------------------------------

class GatedLauncher:
    def __init__(self):
        self.release = threading.Event()
        self.started = []

    def __call__(self, job, run):
        self.started.append(run["key"])
        self.release.wait(5)
        run["state"] = "completed"


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def orchestrator(tmp_path, launcher):
    return Orchestrator(tmp_path / "kit", tmp_path / "runs", launcher=launcher, catalog=CATALOG)


def test_single_active_job_idempotent_launch_and_sequential_pair(tmp_path):
    launcher = GatedLauncher()
    orch = orchestrator(tmp_path, launcher)
    job = orch.launch("finance_false_approval", ["mock"], "key-1")
    assert orch.launch("finance_false_approval", ["mock"], "key-1")["job_id"] == job["job_id"]
    with pytest.raises(Busy):
        orch.launch("finance_false_approval", ["mock"], "key-2")
    wait_for(lambda: launcher.started == ["mock-baseline"])  # protected waits for baseline: never concurrent
    launcher.release.set()
    wait_for(lambda: job["state"] == "completed")
    assert [r["key"] for r in job["runs"]] == ["mock-baseline", "mock-protected"] and job["pair_complete"]
    assert orch.active is None


def test_cancel_prevents_queued_runs_and_marks_the_comparison_incomplete(tmp_path):
    launcher = GatedLauncher()
    orch = orchestrator(tmp_path, launcher)
    job = orch.launch("finance_false_approval", ["mock"], "k")
    wait_for(lambda: launcher.started)
    orch.cancel(job["job_id"])
    launcher.release.set()
    wait_for(lambda: job["state"] == "cancelled")
    assert job["runs"][1]["state"] == "skipped" and launcher.started == ["mock-baseline"]
    assert job["pair_complete"] is False


def test_invalid_input_is_rejected_before_any_work(tmp_path):
    orch = orchestrator(tmp_path, GatedLauncher())
    for scenario, engines in (("../etc", ["mock"]), ("finance_false_approval", ["gpt"]),
                              ("finance_false_approval", []), ("finance_false_approval", ["mock", "mock"])):
        with pytest.raises(ValueError):
            orch.launch(scenario, engines, "k")
    assert orch.active is None and not orch.jobs


def test_restart_marks_unfinished_work_interrupted_without_relaunching(tmp_path):
    job_dir = tmp_path / "runs" / "J1"
    job_dir.mkdir(parents=True)
    (job_dir / "job.json").write_text(json.dumps({"job_id": "J1", "state": "running", "created_at": "x", "runs": [
        {"key": "mock-baseline", "state": "running", "pids": []}, {"key": "mock-protected", "state": "queued", "pids": []}]}))
    launcher = GatedLauncher()
    orch = orchestrator(tmp_path, launcher)
    assert orch.jobs["J1"]["state"] == "interrupted"
    assert {r["state"] for r in orch.jobs["J1"]["runs"]} == {"interrupted"}
    assert orch.active is None and not launcher.started


def test_event_reader_holds_back_a_torn_tail(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"seq": 0, "type": "a"}) + "\n" + json.dumps({"seq": 1, "type": "b"}) + "\n" + '{"seq": 2, "ty')
    events, pending = read_events(path, after=0)
    assert [e["seq"] for e in events] == [1] and pending


def test_http_mutations_need_the_session_token_and_same_origin(tmp_path):
    orch = orchestrator(tmp_path, GatedLauncher())
    client = TestClient(create_app(orch, 8090))
    page = client.get("/")
    assert page.status_code == 200 and "Content-Security-Policy" in page.headers
    token = page.text.split('name="guardyn-session" content="')[1].split('"')[0]
    body = {"scenario_id": "finance_false_approval", "engines": ["mock"], "idempotency_key": "k"}
    assert client.post("/api/jobs", json=body).status_code == 403
    assert client.post("/api/jobs", json=body, headers={"x-guardyn-session": token, "origin": "http://evil.example"}).status_code == 403
    assert client.get("/api/jobs/nope/runs/..%2F..%2Fetc/events").status_code == 404
    assert not orch.jobs


# ---- labels cannot steer decisions ---------------------------------------------------------------

def test_relabelled_reporting_metadata_does_not_change_guardyn_verdicts():
    from app import suspicion
    from app.flow.engine import evaluate
    from tests.helpers import real_requests

    requests = real_requests()[:40]
    verdicts = []
    for label in ("finance_false_approval-http_defense-s0", "relabelled-benign-demo-s9"):
        suspicion.reset()
        verdicts.append([evaluate(r.model_copy(update={"run_id": label}))[0].decision for r in requests])
    assert verdicts[0] == verdicts[1]
