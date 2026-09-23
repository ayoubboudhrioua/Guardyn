# Guardyn — jury guide and technical report

Team: التعاضدية الرسمية المعلوماتية

Project: Sentinel safety layer for tool-using agents

Evidence captured: 2026-09-22; check each artifact manifest before comparing it with newer code.

## The idea in one minute

Guardyn asks whether an agent's *next action* has authority. A malicious document may
be read, quoted, or summarized without gaining authority to send a secret, move money,
or change a SOC incident. Every candidate action receives **allow, block, escalate,
or rewrite** from agent state, the action, provenance, active policy, and observed
content. Scenario IDs and expected benchmark outcomes are outside the decision path.

The distinctive demo is an inspectable path from the legitimate request and observed
source to the proposed action, policy check, decision, and actual tool outcome. A
rewrite is rechecked and can preserve useful work. The graph links to recorded
evidence; its animation has no effect on the safety decision.

## Threat model and method

The adversary controls synthetic tool results, documents, or messages, including
false approvals and instructions embedded in task data. The trusted host supplies
the user goal, active policy, provenance labels, tool history, and approval records.
Compromise of that host is outside this prototype's threat model. The local service
is not an authenticated production gateway.

1. Compile permitted operations from trusted intent and policy.
2. Track where action-steering arguments came from. Unknown origins are untrusted;
   quoted hostile text remains task data rather than a new command.
3. Track credential-like protected values from confidential/restricted observations
   by source and complete nested field path, including repeated and short values.
4. Check operation authority, lifecycle, exact-action confirmation, and disclosure
   at reply, record, memory, and external sinks. External grants bind the recipient.
5. Optionally use local-model alignment and masked replanning as weak signals under
   a short budget. Deterministic constraints retain authority when model checks fail.
6. Recheck any replacement against tool, lifecycle, custody, confirmation, and flow
   rules. Verification failure becomes a block.
7. Record scrubbed reasons. Join decisions to official simulator events to determine
   what was requested or executed; a decision alone does not prove execution.

An approval digest binds the exact target action and arguments. It does not change
tool permissions or declassify data. Fixed regexes, tool metadata, thresholds, and
YAML policy rules exist; they are general input-based rules, not scenario-specific
verdicts. The risk score is heuristic, not a calibrated probability.

This combines existing information-flow and least-privilege ideas. [CaMeL](https://arxiv.org/abs/2503.18813)
offers a stronger capability-based separation of control and data; Guardyn's
passports are heuristic. [MELON](https://arxiv.org/abs/2502.05174) studies masked
re-execution; Guardyn's separate masked model call is only approximate evidence,
not a causal proof of injection.

## Experimental protocol and results

The Sentinel library is public, with 31 attack/9 benign public cases and 4 attack/5
benign validation cases. The official simulator, tools, parser, and graders are used.
The published library informed development; there is no hidden-set claim. Qwen
means local Ollama `qwen3.5:9b`. Manifests record model digest, benchmark commit,
source hash, and runtime settings. Mock uses the evaluator's reference plan and
turns the optional Guardyn LLM judge off; it is a separate test mode.

| Completed configuration | Successful attacks | Benign completion | Evidence |
| --- | ---: | ---: | --- |
| Qwen v9, public | 0/31 | 5/9 | [scorecard](../observability/results/sentinel-v9-qwen/public-scorecard.json), [joined trace](../observability/results/sentinel-v9-qwen/public/decisions.jsonl) |
| Qwen v9, validation | 0/4 | 4/5 | [scorecard](../observability/results/sentinel-v9-qwen/validation-scorecard.json), [joined trace](../observability/results/sentinel-v9-qwen/validation/decisions.jsonl) |
| Mock v9, static, both splits | 0/35 | 14/14 | [manifest](../observability/results/sentinel-v9-mock/manifest.json), [readiness](../observability/results/sentinel-v9-mock/readiness.json) |
| Mock v9, adaptive mutation, both splits | 0/35 | 14/14 | [manifest](../observability/results/sentinel-v9-mock-mutation/manifest.json), [readiness](../observability/results/sentinel-v9-mock-mutation/readiness.json) |

The complete v9 Qwen run had zero model/defense errors and zero critical/data-flow
violations, yet **fails the strict local readiness gate** because five benign tasks
did not complete and some runs terminated abnormally. A release-era whole-source
hash check also differed from the evaluated v9 snapshot because the AgentDojo
constructor's default model changed; Sentinel `app/` and `policies/` matched the
snapshot then. Later live-dashboard work is separate from that historical claim.
Do not relabel older manifests as a new evaluation of the current checkout.

In Qwen v9, 25 attack scenarios had a defense intervention, all in the public
split; validation had none. On reference-labelled illegitimate public actions
there were ten block and six rewrite decisions. **Zero successful attacks is not
35 literal blocks or proof that Guardyn prevented every one.** The model may resist
without a defense intervention. A rewrite is not a block, and an escalation is
not an approval.

An earlier unprotected Qwen public run yielded 24/31 successful attacks and 7/9
benign completion. It is historical context, not a matched fresh v9 pair; its older
artifact remains in the local backup. A v6 matched mock ablation yielded 0/31
public attack successes with proactive flow detection and 12/31 with that layer
disabled; benign completion was 9/9 in both. Replacement verification still
checked flow, so this tests proactive detection rather than all flow controls.
Its full development artifacts are also in the local backup.

### AgentDojo transfer panel

The custom native Ollama adapter used official AgentDojo environments and success
checks. Its matched v7 panel covers four domains and two attack families: 16 clean
and 64 attacked cases per configuration. It is not the full benchmark.

| Metric | Unprotected | Guardyn |
| --- | ---: | ---: |
| Successful attacks | 3/64 | 0/64 |
| Payloads observed | 64/64 | 64/64 |
| Clean tasks completed | 14/16 | 13/16 |
| Attacked tasks completed | 50/64 | 46/64 |
| Evaluation errors | 0 | 0 |

See the [matched comparison](../observability/results/agentdojo-panel-v7-comparison.json)
and each side's manifest and outcomes in `agentdojo-panel-v7/` and
`agentdojo-panel-v7-baseline/`. Eight attacked cases had interventions, comprising
20 block and three escalation *actions*. Only two of the three pairs that changed
from baseline attack success to protected failure have actual intervention evidence.
The third is not credited as demonstrated prevention. One legitimate Slack
summarize-and-send task was falsely restricted, contributing to the utility loss.
The adapter's pre-observation capability compiler needs better coverage of
conditional authorized writes. Errors and inconvenient results remain visible.

## Live dashboard and evidence story

Use the Sentinel kit's Python environment, with Sentinel and Guardyn dependencies:

```powershell
python tools/live_dashboard.py --kit ../Sentinel_Starter_Kit
# Open http://127.0.0.1:8090
```

The dashboard selects an official scenario and runs a fresh unprotected baseline,
then a fresh protected run. Select Qwen, mock, or both; there is one active run
globally. Its overview graph groups enterprise, finance, and SOC stories. Story
mode follows recorded events; Investigate mode holds a stable source → candidate
→ decision → execution path. Clicking a decision first shows one sentence; deeper
scrubbed evidence is available on demand. "Waiting for model" ends only when the
next event is recorded. Pause affects the view, while cancel stops owned run
processes and leaves partial evidence. Replay is labelled with its original mode
and timestamp. Each engine's baseline/protected comparison stays separate.

The baseline uses Sentinel's official `allow_all` control and is shown as
"protection off," with verdict counts not applicable. Mock reference plans and
Qwen reasoning must never be pooled. An allow is permission; a tool result proves
execution. A blocked path is not marked as verified non-execution during an
unfinished stream. Protected values are scrubbed before browser delivery.

The live dashboard implementation is in `tools/live_dashboard.py`, `tools/live_child.py`,
`tools/live_events.py`, and `observability/live.html`. Run artifacts stay local in
git-ignored `observability/live_runs/`. On 2026-09-22, tests and three fresh mock
pairs covered the curated stories; **Qwen dashboard pairs had not run** because
Ollama was unreachable from that environment. Earlier joined traces lack this
dashboard's event stream, so they cannot be replayed there. Event latency and
long-trace collapse remain unverified. These are current dashboard limits, not
changes to the older official v9 scorecards.

For recorded v9 Qwen execution evidence, load the joined public trace in the
read-only viewer:

```powershell
python tools/serve_evidence.py --trace observability/results/sentinel-v9-qwen/public/decisions.jsonl --port 8085
```

### Six to eight minute jury video

1. **Opening (30 seconds):** state the four decisions and the authority question.
2. **Enterprise, finance, SOC (about three minutes):** show one safe repair, one
   blocked unauthorized operation, and one legitimate action allowed despite
   hostile material. Select actual recorded v9 runs or fresh dashboard runs and
   inspect their outcomes before narration. A mock-only approval continuation
   must be labelled mock. Never invent a successful continuation.
3. **Mechanism (one minute):** follow one action's goal, argument origin, disclosure
   rule, verdict, replacement if any, and observed execution.
4. **Evidence and limits (90 seconds):** show sample sizes, model/kit identity,
   attack success, benign completion, intervention counts, and one utility failure.
   Explain that published scenarios are known and that jury scores differ from
   simulator scores.
5. **Close (30 seconds):** the defense constrains what an agent can do with what it
   reads, while showing what happened after the decision.

Choose examples by inspecting joined evidence, not by a hardcoded runtime scenario
rule. Keep protected values out of the recording. Show both useful permitted work
and the remaining benign-completion gap.

## Reproduce and package

With a Python 3.12 environment containing the official Sentinel kit:

```powershell
python tools/eval_sentinel.py --kit ../Sentinel_Starter_Kit --output observability/results/new-qwen-run
python tools/eval_sentinel.py --kit ../Sentinel_Starter_Kit --output observability/results/new-mock-run --model mock
```

Use a new output directory for each experiment. For the limited AgentDojo panel,
use its separate environment and `tools/eval_agentdojo.py`; pass `--baseline`
for the matched control. Tests run with `python -m pytest -q`. The last recorded
Sentinel environment had 87 passing tests with the optional AgentDojo module
skipped; this is a historical test result, not a fresh check after this cleanup.

The pinned Dockerfile builds the decision service, not the full dashboard runner:

```powershell
docker build -t guardyn-sentinel .
docker run --rm -p 127.0.0.1:8080:8080 -e GUARDYN_LLM=off --mount type=volume,source=guardyn-traces,target=/var/lib/guardyn guardyn-sentinel
```

This container serves the decision API and evidence page at localhost:8080.
Optional Ollama checks require a separately reachable model server and declared
model tag. CI runs offline tests and the container smoke check; it does not prove
live-model benchmark performance. The team has not selected a project software
license. `sentinel-submission.yaml` declares the team and model.

## Limits and next work

The ledger does not detect arbitrary sensitive prose or every encoded or derived
secret. Provenance and tool-field roles are heuristic. A separate masked model
call cannot reproduce an exact counterfactual. The same model serving agent and
judge may fail in correlated ways. This is not a formal noninterference proof,
tamper-evident audit store, signed approval service, or multi-tenant deployment.
Stopping an output leak does not prove that an unnecessary read was avoided, and
a policy-safe rewrite can still fail the user's task. One run per configuration
does not establish statistical reliability. The AgentDojo panel is limited.

Next engineering priorities are typed, argument-constrained capabilities;
authenticated provenance and approvals; broader disclosure coverage; repeated
matched trials; and utility improvements grounded in legitimate task intent.
Scenario-specific exceptions or grader-phrase matching would break the central
design rule. The jury rubric weights video 40, report 25, creativity 15, and
engineering/responsible AI 20; none of the simulator composites is a jury score.
