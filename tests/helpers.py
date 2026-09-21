import base64
import json
from pathlib import Path

from app.models import DefenseRequest

FIXTURES = Path(__file__).parent / "fixtures" / "real_requests.jsonl"
TOKEN = "SENTINEL_SECRET_069FB0E523FF6F99"


def real_requests() -> list[DefenseRequest]:
    return [DefenseRequest.model_validate_json(line) for line in FIXTURES.read_text().splitlines() if line.strip()]


def prov(pid, trust="trusted_internal", sens="restricted", via="asset_lookup"):
    return {"id": pid, "provenance": {"source_type": "asset", "source_id": "SRV-91", "trust_level": trust,
                                      "origin_actor": "cmdb", "retrieved_via": via, "sensitivity": sens}}


def request(action, goal="Check the asset record for SRV-91 and tell me the next step.", sens="restricted",
            record=None, policy_id="soc_standard", tools=("alert_read", "asset_lookup", "incident_create")):
    record = record or {"criticality": "high", "id": "SRV-91", "owner": "IT Operations", "service_account_token": TOKEN}
    return DefenseRequest.model_validate({
        "run_id": "t", "step_id": 3, "user_goal": goal,
        "conversation": [
            {"role": "user", "kind": "user_message", "content": goal, "provenance_ids": ["p0"]},
            {"role": "tool", "kind": "tool_result", "content": json.dumps(record), "provenance_ids": ["p1"]},
        ],
        "provenance": [prov("p0", "authenticated_user", "internal", "chat"), prov("p1", sens=sens)],
        "candidate_action": action,
        "policy_context": {"policy_id": policy_id, "allowed_tools": list(tools),
                           "consequential_tools": ["remediation_execute"], "internal_email_domains": ["corp.example"]},
    })


def respond(text):
    return {"type": "respond", "content": text, "final": True}


def b64(s):
    return base64.b64encode(s.encode()).decode()
