# Guardyn

Guardyn is an action-level safety layer for tool-using agents in synthetic
enterprise, financial-services, and SOC scenarios. It decides **allow, block,
escalate, or rewrite** using the agent state, proposed action, provenance, active
policy, and observed content. Scenario IDs and expected outcomes do not select
runtime verdicts.

The [jury guide and technical report](docs/JURY_GUIDE.md) contains the threat model,
mechanism, current evidence, limitations, demo outline, and reproduction notes.

## Evidence at a glance

In the completed official Sentinel v9 qwen3:8b run, attack success was **0/35**
and benign completion **9/14**, with no model or defense errors. The strict local
readiness gate fails on benign utility and normal termination. Only 25 attack
scenarios had a defense intervention; zero attack success does not mean 35 literal
blocks. Separate static and adaptive mock runs each achieved 0/35 attack success
and 14/14 benign completion. Mock uses a reference plan and is not a Qwen result.

The matched AgentDojo v7 panel is limited to 64 attacked and 16 clean cases per
configuration: baseline attack success 3/64 versus protected 0/64, with clean
completion 14/16 versus 13/16. See the guide for exposure, intervention evidence,
utility cost, and the limits of causal attribution.

Current scorecards, manifests, and scrubbed joined traces are under
`observability/results/sentinel-v9-*` and
`observability/results/agentdojo-panel-v7*`. Older development results are kept
in the local pre-cleanup backup rather than the branch. Generated new runs stay
local under ignored result/live-run directories.

## Run the decision service

Use Python 3.12 and install `requirements.lock.txt` in a virtual environment.
The optional local-model judge expects Ollama and the declared `qwen3:8b` tag.

```powershell
python -m pip install -r requirements.lock.txt
$env:GUARDYN_LLM = "off"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080` for the decision trace viewer. The service exposes
`POST /v1/decision`, `GET /v1/trace`, and `GET /healthz`. A decision trace alone
does not prove whether the simulator executed a tool.

## Run the live Sentinel dashboard

Use the pinned Python 3.12 Docker image to avoid mixing the kit and system Python
environments. The official Sentinel checkout remains on your machine and is mounted
read-only; live artifacts persist in a named Docker volume. From this repository in
PowerShell:

```powershell
$kit = (Resolve-Path ../Sentinel_Starter_Kit).Path
docker build -t guardyn-live .
docker run --rm -p 127.0.0.1:8090:8090 --mount "type=bind,src=$kit,dst=/sentinel-kit,readonly" --mount "type=volume,src=guardyn-live-runs,dst=/var/lib/guardyn/live_runs" -e OLLAMA_HOST=http://host.docker.internal:11434 guardyn-live
```

Ollama must be reachable from the container at `host.docker.internal:11434` for
Qwen runs. Mock runs do not need Ollama. The dashboard also runs without Docker
when launched from a Python 3.12 environment containing both the official kit and
Guardyn dependencies:

```powershell
python tools/live_dashboard.py --kit ../Sentinel_Starter_Kit
```

Open `http://127.0.0.1:8090`. Select an official scenario and run fresh
baseline → protected pairs with Qwen, mock, or both. Only one run executes at a
time. Story and Investigate views use the same scrubbed event evidence. Qwen
requires the exact installed Ollama model; the dashboard does not silently
substitute mock. Current implementation and unverified areas are described in the
[jury guide](docs/JURY_GUIDE.md#live-dashboard-and-evidence-story).

For recorded v9 Qwen execution evidence, use the read-only viewer:

```powershell
python tools/serve_evidence.py --trace observability/results/sentinel-v9-qwen/public/decisions.jsonl --port 8085
```

## Test and package

```powershell
python -m pytest -q
docker build -t guardyn-live .
python tools/package_release.py --output dist/guardyn-source-new
```

The Docker image starts the live Sentinel dashboard by default and launches the
decision API as an owned child during protected runs. CI runs offline tests and a
container smoke check; it does not run the local Ollama benchmark. Use a new
release output directory for each source bundle. `sentinel-submission.yaml`
declares the team and model. No project software license has been selected.
