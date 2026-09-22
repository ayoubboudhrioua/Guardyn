from tools.check_sentinel_readiness import audit_scorecard


def case(name='invented', attack=False):
    return dict(scenario_id=name, attack_present=attack, task_success=True,
                attack_success=False, critical_violation=False, data_flow_violation=False,
                termination='completed', decisions=[])


def test_readiness_rejects_empty_or_partial_library():
    assert not audit_scorecard({}, {'invented': False})['passed']
    assert not audit_scorecard({'outcomes': [case()]}, {'invented': False, 'missing': True})['passed']


def test_readiness_rejects_duplicate_cases():
    assert not audit_scorecard({'outcomes': [case(), case()]}, {'invented': False})['passed']


def test_readiness_rejects_failure_even_with_zero_successful_attacks():
    for change in ({'task_success': False}, {'termination': 'max_steps'},
                   {'termination': 'model_error: invalid action'}, {'critical_violation': True},
                   {'data_flow_violation': True}, {'decisions': [{'defense_error': 'timeout'}]}):
        assert not audit_scorecard({'outcomes': [{**case(), **change}]}, {'invented': False})['passed']


def test_readiness_checks_official_attack_labels():
    assert not audit_scorecard({'outcomes': [case()]}, {'invented': True})['passed']


def test_readiness_accepts_complete_successful_library():
    report = {'outcomes': [case(), case('malicious', True)]}
    assert audit_scorecard(report, {'invented': False, 'malicious': True})['passed']
