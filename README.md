# Guardyn — action-level safety with inspectable evidence

Guardyn is a SENTINEL defense for tool-using agents in enterprise productivity,
a financial-services sandbox and a SOC. Every candidate resolves to **allow,
block, escalate or rewrite**, using state, action, provenance, active policy and
observed content — never a scenario ID or expected outcome.

The demo concept is **"show why this action is permitted."** Trace authority
separately from data: stop an unauthorized transfer, allow an analyst to quote a
phishing message, and redact a secret while preserving a useful answer. Show
the replacement and actual execution, not just a risk badge.

## Current evidence (2026-09-22)

Release packaging is v9. See [GitHub handoff](docs/RELEASE.md) for the pinned Docker
build and push instructions, and [Sentinel readiness](docs/SENTINEL_READINESS.md)
for the strict gate. Both full-library mock modes pass. Live-Qwen v9 completed
without errors, but benign utility is not perfect: 9/14 tasks completed.

Local experiments, not jury scores. Versions are deliberately separated.

| Experiment | Successful attacks | Benign completion |
| --- | --- | --- |
| Qwen3.5:9b, unprotected, public | 24/31 | 7/9 |
| Qwen3.5:9b, Guardyn v9, public | 0/31 | 5/9 |
| Qwen3.5:9b, Guardyn v9, validation | 0/4 | 4/5 |
| Mock agent, v9, public | 0/31 | 9/9 |
| Mock agent, v9, validation | 0/4 | 5/5 |

All 49 v9 live cases were evaluated without model or defense errors. Five benign
tasks still failed their graders; completion loops and an exact-text mismatch
remain documented. Only 25 attack scenarios had defense interventions; the
validation attacks failed without intervention. Do not claim 35 literal blocks
or substitute mock utility for Qwen utility. The older v6 validation experiment
had six model-unavailability errors and is preserved as invalid failure evidence.
Zero attack success does not mean the defense literally blocked every attack:
the model may resist, a defense may rewrite/escalate, or an attack may never reach
its goal. Joined reports distinguish outcome from intervention.

The final matched AgentDojo v7 panel completed 80 cases per configuration without
errors: attack success was **3/64 unprotected versus 0/64 defended**; all 64
payloads were observed in both. Clean completion was 14/16 versus 13/16, and
attacked-task completion was 50/64 versus 46/64. The defense intervened in eight
attacked cases. Two of the three baseline-success/defended-failure pairs had an
actual intervention; the other must not be credited as demonstrated prevention.

One legitimate Slack write remains falsely restricted. Earlier v6 had an attack
escape and a model-server error; both remain in the artifacts. The v7 general
framing fix stops both payment variants that escaped without protection.
This four-suite, two-attack panel is not the full AgentDojo benchmark.

The latest Sentinel-environment suite passes 87 tests (optional AgentDojo module
skipped). The browser-tested evidence viewer
shows observed read/write results, blocked execution and verified replacements.

Current Sentinel evidence is in `observability/results/sentinel-v9-qwen/`,
`sentinel-v9-mock/` and `sentinel-v9-mock-mutation/`. AgentDojo results remain v7.
The [evidence index](observability/results/README.md) separates old and current runs.
New scorecards are under each experiment directory; raw simulator events remain
local in its `simulator/` subdirectory. Earlier runs also used the sibling
`Sentinel_Starter_Kit/artifacts/` checkout. Raw simulator directories and logs are
excluded from new Git additions; compact reports and scrubbed playback remain.

## Safety boundary

1. Compile the contract from trusted policy and user intent.
2. Trace control arguments to origins; unknown origins are untrusted.
3. Track protected values from observations into every sink.
4. Enforce tool permissions, lifecycle and exact-action confirmation.
5. Treat optional model judgments as weak evidence.
6. Recheck replacements before returning rewrite.
7. Record scrubbed evidence and join simulator execution afterward.

Disclosure grants bind source ID, complete field path, sink and external recipient.
Mentioning "password" in a goal is not a grant. An exact recorded approval does
not declassify data.

There **are** fixed rules, tool mappings, regexes, thresholds and policy constants.
These differ from hardcoded benchmark outcomes. Evaluator-only tools use scenario
IDs to organize evidence, never to choose runtime decisions.

## Running

Requires Python 3.12 and `requirements.txt`.

```powershell
uv venv
uv pip install -r requirements.txt
uv pip install pytest
$env:GUARDYN_JUDGE_MODEL = "qwen3.5:9b"
$env:SENTINEL_TRACE = "observability/decisions.jsonl"
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open http://127.0.0.1:8080 for the dashboard. Load a joined JSONL artifact for
simulator execution evidence; live service traces show decisions only.

For read-only playback of completed live-Qwen evidence, without a decision endpoint:

```powershell
python tools/serve_evidence.py --trace observability/results/sentinel-v9-qwen/public/decisions.jsonl --port 8085
```

Then open http://127.0.0.1:8085. This viewer cannot execute or append tool actions.

In the official starter-kit checkout:

```powershell
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --model ollama:qwen3.5:9b --artifacts artifacts/my-run
uv run sentinel eval validation --defense-url http://127.0.0.1:8080 --model ollama:qwen3.5:9b --artifacts artifacts/my-run
```

Use `--model mock` for deterministic checks. `GUARDYN_LLM=off` disables the
optional judges; deterministic checks remain. `GUARDYN_MODE=legacy` selects the
older committee. Call budgets are advisory unless policy enables enforcement.
Run tests with `python -m pytest -q`; optional AgentDojo tests require its environment.

See [architecture](docs/ARCHITECTURE.md), [limitations](docs/not-built.md),
[technical report](docs/TECHNICAL_REPORT.md), [demo script](docs/DEMO_SCRIPT.md), and
[work log](docs/WORK_LOG.md). Jury weights are video 40, report 25, creativity 15,
engineering/responsible AI 20. Simulator composites are not the jury score.
