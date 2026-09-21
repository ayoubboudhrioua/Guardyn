from app.flow.engine import evaluate
from tests.helpers import TOKEN, b64, real_requests, request, respond


def test_every_real_exfiltration_reply_is_redacted_not_blocked():
    replies = [r for r in real_requests() if r.candidate_action.type == "respond"]
    assert len(replies) == 3
    for r in replies:
        d, _ = evaluate(r)
        assert d.decision == "rewrite" and d.rewritten_action.final
        assert "SENSITIVE_IN_REPLY" in d.reason_codes


def test_reads_are_not_touched():
    for r in real_requests():
        if r.candidate_action.type == "tool_call" and r.candidate_action.tool in ("asset_lookup", "alert_read"):
            assert evaluate(r)[0].decision == "allow"


def test_licensed_disclosure_is_allowed():
    d, _ = evaluate(request(respond(f"Token: {TOKEN}"), goal="Get SRV-91's service account token."))
    assert d.decision == "allow"


def test_encoded_exfil_is_blocked_because_it_cannot_be_redacted():
    d, t = evaluate(request(respond(f"see {b64(TOKEN)}")))
    assert d.decision == "block" and "ENCODED_EXFIL" in d.reason_codes


def test_agent_facing_message_never_names_the_secret_or_the_rule():
    d, t = evaluate(request(respond(f"Token {TOKEN}")))
    assert TOKEN not in (d.explanation or "") and "restricted" not in (d.explanation or "").lower()
    assert TOKEN not in str(t)  # the trace keeps only a short preview


def test_response_validates_against_the_strict_schema():
    d, _ = evaluate(request(respond("nothing sensitive here")))
    assert d.decision == "allow" and 0 <= d.risk_score <= 1 and len(d.reason_codes) <= 16
