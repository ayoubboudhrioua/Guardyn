from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_submission_manifest_is_valid_yaml_and_matches_judge_model():
    from app.flow.llm import MODEL
    manifest = yaml.safe_load((ROOT / 'sentinel-submission.yaml').read_text())
    assert manifest['models'][0]['name'] == MODEL
    assert manifest['kind'] == 'defense'
    assert manifest['api_version'] == 'v1'


def test_container_runs_live_dashboard_with_python_312_and_nonroot_artifacts():
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert dockerfile.startswith('FROM python:3.12-slim@sha256:')
    assert 'COPY tools ./tools' in dockerfile
    assert 'COPY observability/live.html ./observability/live.html' in dockerfile
    assert 'mkdir -p /var/lib/guardyn/live_runs' in dockerfile
    assert 'chown -R 10001:10001 /var/lib/guardyn' in dockerfile
    assert 'USER 10001:10001' in dockerfile
    assert 'CMD ["python", "tools/live_dashboard.py"' in dockerfile
    assert '"--kit", "/sentinel-kit"' in dockerfile
