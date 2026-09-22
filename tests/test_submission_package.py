from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_submission_manifest_is_valid_yaml_and_matches_judge_model():
    from app.flow.llm import MODEL
    manifest = yaml.safe_load((ROOT / 'sentinel-submission.yaml').read_text())
    assert manifest['models'][0]['name'] == MODEL
    assert manifest['kind'] == 'defense'
    assert manifest['api_version'] == 'v1'


def test_container_includes_dashboard_and_nonroot_trace_directory():
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert 'COPY observability/index.html ./observability/index.html' in dockerfile
    assert 'SENTINEL_TRACE=/var/lib/guardyn/decisions.jsonl' in dockerfile
    assert 'mkdir -p /var/lib/guardyn' in dockerfile
    assert 'chown 10001:10001 /var/lib/guardyn' in dockerfile
    assert 'USER 10001:10001' in dockerfile
