import pytest
from tools.compare_agentdojo import MATCHED_FIELDS, summarize
from tools.report_sentinel import error_accounting, execution_summary


@pytest.mark.parametrize("event_type", ["retrieval_result", "tool_result"])
def test_execution_summary_includes_reads_and_writes_without_payloads(event_type):
    event = {"type": event_type, "payload": {"tool": "invented_tool", "succeeded": True,
                                              "result": "private-value", "effects": ["private-value"]}}
    result = execution_summary([event])
    assert result["tool_results"] == [{"tool": "invented_tool", "succeeded": True}]
    assert "private-value" not in str(result)


def test_tool_request_is_not_evidence_of_success():
    result = execution_summary([{"type": "tool_request", "payload": {"tool": "invented_tool"}}])
    assert result["tools_requested"] == ["invented_tool"]
    assert result["tool_results"] == []
    assert not result["response_emitted"]


def test_sentinel_outage_is_not_counted_as_a_prevented_attack():
    failed = {"scenario_id": "invented-error", "attack_present": True, "attack_success": False,
              "termination": "model_error: unavailable", "decisions": []}
    report = error_accounting([failed])
    assert not report["evaluation_complete_without_errors"]
    assert report["valid_attack_count"] == 0
    assert report["model_error_scenarios"] == ["invented-error"]


def manifests():
    base = {field: "same" for field in MATCHED_FIELDS}
    base.update(suites=["synthetic"], defended=False)
    return base, {**base, "defended": True}


def row(case, attacked=False, utility=True, success=False, error=None):
    result = dict(case=case, suite="synthetic", attacked=attacked, utility=utility,
                  attack_success=success, attack_exposed=attacked, decisions={"allow": 1})
    if error:
        result["error"] = error
    return result


def test_comparison_rejects_different_sources():
    base, defense = manifests()
    defense["source_digest"] = "changed"
    with pytest.raises(ValueError, match="source_digest"):
        summarize(base, defense, [], [])


def test_comparison_never_counts_error_as_attack_prevention():
    base, defense = manifests()
    report = summarize(base, defense, [row("attack", True, success=True)],
                       [row("attack", True, error="timeout")])
    assert report["paired_valid_cases"] == 0
    assert report["baseline_success_defended_failure_cases"] == []
    assert report["defense_errors"] == ["attack"]


def test_comparison_distinguishes_resistance_and_intervention():
    base, defense = manifests()
    blocked = row("intervened", True)
    blocked["decisions"] = {"block": 1}
    report = summarize(base, defense,
                       [row("resisted", True, success=True), row("intervened", True, success=True)],
                       [row("resisted", True), blocked])
    assert len(report["baseline_success_defended_failure_cases"]) == 2
    assert report["of_those_with_observed_defense_intervention"] == ["intervened"]


def test_successful_retry_does_not_hide_original_error_attempt():
    base, defense = manifests()
    report = summarize(base, defense, [row("case", True)],
                       [row("case", True, error="server unavailable"), row("case", True)])
    assert report["paired_valid_cases"] == 1
    assert report["defense_errors"] == []
    assert report["defense_error_attempts"] == 1
    assert report["defense_attempt_count"] == 2
