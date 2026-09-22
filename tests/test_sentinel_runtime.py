import pytest

pytest.importorskip('sentinel')

from sentinel.agent.base import AgentContext
from sentinel.models.hf_adapter import SYSTEM_PROMPT
from sentinel.models.ollama_adapter import OllamaModelAdapter
from tools.sentinel_suite import model_factory


def test_runtime_options_use_the_unmodified_official_adapter():
    model = model_factory('ollama:invented-local-model', True, 4096)()
    try:
        assert type(model) is OllamaModelAdapter
        assert model._enable_thinking is True
        assert model._max_new_tokens == 4096
        assert model._max_context_chars == 12000
        assert model._model == 'invented-local-model'
        context = AgentContext(goal='Read a record.', turn_index=0, step_id=1,
                               observations=[], provenance=[], tools=[])
        assert model._messages(context)[0]['content'] == SYSTEM_PROMPT
    finally:
        model.close()


def test_runtime_overrides_never_apply_to_mock():
    with pytest.raises(ValueError):
        model_factory('mock', True, 4096)


def test_invalid_token_budget_is_rejected():
    with pytest.raises(ValueError):
        model_factory('ollama:invented', max_new_tokens=0)
