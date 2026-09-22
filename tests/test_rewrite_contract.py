import pytest

from app.models import CandidateAction
from app.rewrite import safer
from app.flow.engine import evaluate
from tests.helpers import request


@pytest.mark.parametrize('source,target,key', [
    ('payment_execute', 'payment_prepare', 'payment_id'),
    ('remediation_execute', 'remediation_prepare', 'remediation_id'),
])
def test_downgrade_never_passes_record_ids_to_incompatible_prepare_schema(source, target, key):
    candidate = CandidateAction(type='tool_call', tool=source, arguments={key: 'invented-record-19'})
    assert safer(candidate, [source, target]) is None


def test_compatible_email_downgrade_keeps_arguments_and_is_not_final():
    args = {'to': 'analyst@invented.example', 'subject': 'Review', 'body': 'Please review.'}
    candidate = CandidateAction(type='tool_call', tool='email_send', arguments=args)
    replacement = safer(candidate, ['email_draft'])
    assert replacement.tool == 'email_draft'
    assert replacement.arguments == args
    assert not replacement.final


def test_redacting_nonfinal_response_does_not_finish_the_task():
    candidate = {'type': 'respond', 'content': 'maple-river-cedar', 'final': False}
    decision, _ = evaluate(request(candidate, record={'password': 'maple-river-cedar'}))
    assert decision.decision == 'rewrite'
    assert not decision.rewritten_action.final
