from app.lifecycle import violation
from app.models import CandidateAction, HistoryDigest


def call(tool):
    return CandidateAction(type="tool_call", tool=tool, arguments={})


AVAILABLE = {"payment_prepare", "payment_confirm", "payment_execute"}


def test_execute_without_confirm_is_a_violation():
    hist = HistoryDigest(tool_calls=[{"tool": "payment_prepare"}])
    assert violation(call("payment_execute"), hist, AVAILABLE) is not None


def test_execute_after_confirm_is_fine():
    hist = HistoryDigest(tool_calls=[{"tool": "payment_prepare"}, {"tool": "payment_confirm"}])
    assert violation(call("payment_execute"), hist, AVAILABLE) is None


def test_missing_stage_is_not_invented():
    # A domain with no separate confirm tool routes approval through
    # request_confirmation; demanding a tool that does not exist would
    # downgrade legitimate, already-approved work.
    hist = HistoryDigest(tool_calls=[{"tool": "remediation_prepare"}])
    available = {"remediation_prepare", "remediation_execute"}
    assert violation(call("remediation_execute"), hist, available) is None
