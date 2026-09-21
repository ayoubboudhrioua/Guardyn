from app.flow import flowpolicy, ledger, policy
from tests.helpers import TOKEN, b64, request, respond


def run(action, **kw):
    req = request(action, **kw)
    pol = policy.select(req)
    atoms = ledger.build(req)
    return req, pol, atoms, flowpolicy.check(req, req.candidate_action, atoms, pol)


def test_unrequested_secret_in_reply_is_a_finding_and_is_redacted():
    req, pol, atoms, found = run(respond(f"Next step: review. The token is {TOKEN}."))
    assert found and found[0].sink == "user_reply" and found[0].encoding == "plain"
    fixed = flowpolicy.redact(req.candidate_action, found)
    assert TOKEN not in fixed.content and "[REDACTED:credential]" in fixed.content
    assert flowpolicy.verified(req, fixed, atoms, pol)


def test_reply_without_the_secret_is_untouched():
    assert run(respond("Review the host and block the domain."))[3] == []


def test_goal_that_asks_for_the_credential_licenses_disclosure():
    goal = "Look up SRV-91 and tell me its service account token."
    assert run(respond(f"The token is {TOKEN}."), goal=goal)[3] == []


def test_goal_that_only_names_the_host_does_not_license_it():
    assert run(respond(f"Host owner IT Ops; {TOKEN}"), goal="Summarise SRV-91.")[3]


def test_spaced_out_secret_is_still_redacted():
    spaced = " ".join(TOKEN)
    req, pol, atoms, found = run(respond(f"code: {spaced}"))
    fixed = flowpolicy.redact(req.candidate_action, found)
    assert fixed is not None and flowpolicy.verified(req, fixed, atoms, pol)


def test_base64_secret_is_flagged_but_cannot_be_cleanly_redacted():
    found = run(respond(f"blob {b64(TOKEN)}"))[3]
    assert found and found[0].encoding == "encoded" and not found[0].redactable


def test_internal_record_write_is_checked_like_the_reply():
    act = {"type": "tool_call", "tool": "incident_create", "arguments": {"title": "t", "summary": TOKEN}}
    found = run(act)[3]
    assert found and found[0].sink == "internal_record"


def test_domain_policy_overrides_base_ceiling():
    # soc allows confidential (not restricted) material into incident records
    act = {"type": "tool_call", "tool": "incident_create", "arguments": {"summary": TOKEN}}
    assert run(act, sens="confidential")[3] == []
    assert run(act, sens="confidential", policy_id="finance_standard", tools=("incident_create",))[3]


def test_partial_leak_is_caught():
    found = run(respond(f"starts {TOKEN[:16]}"))[3]
    assert found and found[0].encoding == "partial"
