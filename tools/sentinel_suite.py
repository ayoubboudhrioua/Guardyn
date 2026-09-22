"""Official Sentinel evaluator with declared runtime-only Ollama settings.

The model, prompt, tools, parser, scenarios, success checks and agent loop are
unchanged. Selection happens only in this evaluator, never inside the defense.
"""
import argparse
import json
from pathlib import Path


def model_factory(model, thinking=False, max_new_tokens=768):
    if max_new_tokens < 1:
        raise ValueError('max_new_tokens must be positive')
    if model.startswith('ollama:'):
        from sentinel.models.ollama_adapter import OllamaModelAdapter
        return lambda: OllamaModelAdapter(model.split(':', 1)[1],
                                         enable_thinking=thinking,
                                         max_new_tokens=max_new_tokens)
    if thinking or max_new_tokens != 768:
        raise ValueError('Runtime overrides require an Ollama model')
    from sentinel.cli import _model_factory
    return _model_factory(model)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--split', choices=['public', 'validation'], required=True)
    parser.add_argument('--defense-url', required=True)
    parser.add_argument('--model', required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--thinking', action='store_true')
    parser.add_argument('--max-new-tokens', type=int, default=768)
    parser.add_argument('--subset', choices=['all', 'benign'], default='all')
    parser.add_argument('--attacker', choices=['static', 'mutation'], default='static')
    parser.add_argument('--attack-mode', choices=['static', 'adaptive'], default='static')
    args = parser.parse_args()
    from sentinel.cli import _defense_factory, _attacker_factory
    from sentinel.config import load_competition
    from sentinel.evaluator.runner import RunConfig, AttackMode, load_suite, evaluate, eval_group_name
    from sentinel.storage.runs import ArtifactStore

    kit = args.kit.resolve()
    scenarios = load_suite(kit / 'scenarios' / args.split)
    if args.subset == 'benign':
        scenarios = [s for s in scenarios if not s.attack.present]
    if not scenarios or any(s.split.value != args.split for s in scenarios):
        raise ValueError('Empty or mismatched scenario selection')
    competition = load_competition(None, kit)
    store = ArtifactStore(args.artifacts)
    group = store.unique_group(eval_group_name(args.split, 'http_defense'))
    config = RunConfig(root=kit, competition=competition,
                       attack_mode=AttackMode(args.attack_mode),
                       model_factory=model_factory(args.model, args.thinking, args.max_new_tokens),
                       include_reference_plan=args.model == 'mock', artifacts=store, artifact_group=group)
    report = evaluate(scenarios, _defense_factory(None, args.defense_url, competition),
                      config, _attacker_factory(args.attacker))
    result = report.participant_view()
    store.write_json('scorecards', group, result)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'scenario_count': report.scenario_count, 'metrics': report.metrics.model_dump(mode='json')}))


if __name__ == '__main__':
    main()
