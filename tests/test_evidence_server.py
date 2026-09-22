import json
from fastapi.testclient import TestClient
from tools.serve_evidence import create_app


def test_evidence_server_is_read_only_and_serves_the_selected_trace(tmp_path):
    path = tmp_path / "evidence.jsonl"
    row = {"run_id": "example", "step_id": 1, "decision": "block"}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    client = TestClient(create_app(path))
    assert client.get("/").status_code == 200
    assert client.get("/v1/trace").json() == [row]
    assert client.post("/v1/decision", json={}).status_code == 404
    assert client.post("/v1/trace", json={}).status_code == 405
    assert path.read_text() == json.dumps(row) + "\n"
