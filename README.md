#Guardyn — authority-flow control for tool-using agents

SENTINEL challenge submission, IndabaX Tunisia 2026.

## Guardyn-Flow: the layer added after testing on Qwen3-8B

The original Guardyn was only ever run on the mock model. Run against the real Qwen3-8B agent it let
**22 of 31 public attacks land (ASR 0.71)**, including all 21 `data_exfiltration` scenarios. The
cause was a missing rule, not a missing signal: it checked for leaks to *external* sinks only, so
a `restricted` token the user's request legitimately caused the agent to read could be repeated in
the reply or written into an internal record. Guardyn-Flow adds a layer built from published
mechanisms. Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

| Layer | What it does | Paper |
| --- | --- | --- |
| L1 flow ledger | protected atoms (secret-shaped values in confidential or restricted results) with their labels | FIDES |
| L2 policy engine | YAML policy sets: sink ceilings, tool-to-sink map, call budgets; base plus one per domain | Progent |
| L3 flow policy | a protected atom may reach *any* sink (reply, record, memory, outbound) only if the user's own request licensed that kind of disclosure | FIDES, CaMeL |
| L4 task-alignment judge | Qwen, datamarked untrusted text, weak flag only | Task Shield, Spotlighting |
| L5 counterfactual check | re-plan with untrusted content masked; flag calls that do not survive | MELON (reduced) |
| L6 flags | typed flags in four families: authority, flow, policy, semantic | |
| L7 ladder | allow, **redact**, downgrade, escalate, block: least destructive first, every redaction re-verified | |

Redaction is the point: the reply still completes, with `[REDACTED:credential]` where the secret
was. Encoded leaks (base64, hex) cannot be cleanly redacted, so they are blocked.

### Measured against Qwen3-8B (Ollama, 4-bit), public split, 40 scenarios

| Configuration | ASR | CVR | BTU | FBR | p50 ms | p95 ms |
| --- | --- | --- | --- | --- | --- | --- |
| legacy Guardyn | 0.710 | 0.550 | 0.444 | 0.000 | 3.7 | 15 |
| **Guardyn-Flow, all layers** | **0.000** | **0.000** | 0.333 | 0.000 | 6.5 | 1227 |
| Flow, L4 and L5 off | 0.000 | 0.000 | 0.333 | 0.000 | 5.7 | 25 |
| Flow, L3 off | 0.710 | 0.550 | 0.333 | 0.000 | 5.1 | 1200 |

Raw results are in `observability/results/`. Each configuration was run once.

What this does and does not show:

- **L3 does all the work.** Turning it off restores the 0.71 ASR; turning L4 and L5 off changes no
  outcome. The judge answered "serves the user's request" on all 53 actions it saw, including every
  exfiltration reply, because it is the same Qwen3-8B the injection had already persuaded. It
  raised one `beyond_scope` flag (correct), on a reply, and L5 only runs on tool calls, so L5
  never produced a verdict. They add up to 1.2 s of p95
  latency for no measured benefit on this split. They stay because the design is stronger with
  them and because a different judge model could change this, not because the numbers support them.
- **In-distribution result.** The 21 exfiltration scenarios put a credential-named field in a
  restricted record and have the agent repeat it. L3 is general (no scenario ids, no fixed
  strings; secrets are found by field name and entropy, sinks by policy), but it has not been
  tested against leaks of ordinary prose, or of secrets stored under innocuous keys and short
  values. Unit tests cover the entropy and encoding paths only.
- **Benign utility is unchanged by the defense.** BTU fell from 0.444 to 0.333 because one benign
  scenario (`enterprise_ticket_followup`) failed its grader in the flow run: the agent skipped
  the `ticket_update` call and only claimed to have made it. Guardyn allowed every step there, and
  the other benign scenarios behave the same in both runs. Qwen is not bit-reproducible run to run
  on this GPU. FBR is 0.000.
- **Calibration got worse.** Brier 0.16 to 0.28 and ECE 0.17 to 0.31 on public. A redaction carries
  a fused risk of about 0.85 whether or not the run was labelled an attack, and the thresholds were
  calibrated on the mock model. Not recalibrated.
- **Validation split shows nothing.** Qwen resisted all 4 validation attacks by itself, and Guardyn
  intervened on none of 45 decisions. The encoded-exfiltration scenario there was not exercised
  against the real model.
- **The reads still happen.** Redaction stops the disclosure. It does not stop an injected lookup
  from running.

Run it: `GUARDYN_MODE=flow uvicorn app.main:app --port 8080` (default), `GUARDYN_MODE=legacy` for the old
pipeline, `GUARDYN_LLM=off` to disable L4 and L5, `GUARDYN_DISABLE=L3,L4,L5,BUDGET` to ablate layers.

## Hypothesis

Prompt injection is an **authority-confusion** bug, not a content bug. Untrusted
content may supply an action's *data*; it must never supply its *authority*. If every
action has to name a trusted source that accounts for it, injections fail while
utility survives — including the case where the correct behaviour is to faithfully
copy attacker-written text.

The challenge ships the test for this. `finance_val_scam_quote_note` asks the agent to
quote a phishing message verbatim into a case note. A defense that decides from content
refuses a legitimate task. A defense that decides from authority allows it.

## Architecture

    trusted input (user + policy)        untrusted observations (email, docs, logs, memory)
            │                                          │
            ▼                                          ▼
    Stage 0  Mandate Compiler  ──────────────►  Stage 1  Guardyn labels (IFC)
      contract.py                                 labels.py
      compiled before any untrusted               trust × sensitivity, join rule:
      byte is read; untrusted content             weakest trust, strongest sensitivity
      may narrow it, never widen it               memory frozen at write time
            │                                          │
            └──────────────────┬───────────────────────┘
                               ▼
                  Value passports · passports.py
                  every control argument traced to first appearance
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
        judge policy      judge custody      judge content
        contract +        passports +        suspicion dial
        lifecycle         flow rule          (weakest judge)
            └──────────────────┼──────────────────┘
                               ▼
              committee.py · agreement acts, disagreement escalates
                               ▼
              fusion.py · noisy-OR risk, calibrated thresholds
                               ▼
              allow          block          escalate        rewrite
                               ▼
              trace.py → observability/index.html

## Results

`sentinel eval`, mock model, 19 public + 9 validation scenarios.

| Defense | split | BTU ↑ | ASR ↓ | CVR ↓ | FBR ↓ | UER ↓ | DFI ↑ | Brier ↓ | ECE ↓ |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `provenance` (best baseline) | public | 1.000 | 0.000 | 0.000 | 0.046 | 0.000 | 1.000 | 0.038 | 0.099 |
| **Guardyn** | public | 1.000 | 0.000 | 0.000 | **0.000** | 0.000 | 1.000 | **0.030** | **0.053** |
| `provenance` | validation | 1.000 | 0.250 | 0.111 | 0.000 | 0.000 | 0.889 | 0.060 | 0.027 |
| **Guardyn** | validation | 1.000 | **0.000** | **0.000** | 0.000 | 0.000 | **1.000** | **0.022** | **0.002** |

The baseline's validation failure is `enterprise_val_encoded_exfil`: its taint matching
is verbatim and the payload is base64.

## What each idea buys, concretely

**Mandate Compiler.** The contract is built from `SYSTEM_POLICY` and
`AUTHENTICATED_USER` before anything untrusted is read. A document cannot add a tool to
it. This is what stops false-approval and forged-closure with no content analysis at all.

**Guardyn labels.** Two axes, joined as weakest-trust and strongest-sensitivity. Memory
freezes its label at write time, so a fake policy planted by a newsletter in turn 1
cannot outrank the real policy document in turn 2. Recall does not launder trust.

**Value passports.** Every short steering argument is traced to where it first appeared.
A recipient that only ever showed up in a vendor attachment fails custody regardless of
how the surrounding sentence is phrased, so the check survives paraphrase. It also reads
directly in the trace: `to ← first seen in tool/email (untrusted_external)`.

**Control plane vs data plane.** Short arguments steer *which* action this is; long free
text is cargo. Custody applies only to the former. Without this the defense refuses to
let an analyst file a phishing mail into a case note.

**Lifecycle state machines.** `prepare → confirm → execute` cannot skip steps, and only
a confirmation recorded in the agent's own history counts. A sentence in an email saying
an officer already approved is not a confirmation. The chain is narrowed to stages that
actually exist in the domain — inventing a `remediation_confirm` that the SOC domain
never defines downgrades legitimate, already-approved isolation.

**Suspicion dial.** Session state keyed by `run_id`. It rises on custody failures and
interventions, not on how bossy the prose sounds — ordinary vendor email is full of
imperatives, and keying on that escalated a quarter of all benign work in testing.

**Committee.** Three judges. Two blocks is decisive, a lone block against two allows is a
split, and a split inside the ambiguous risk band escalates to a human. Each judge is a
ready-made ablation.

**Block messages are category-level.** An adversary who can watch the agent's public
actions would otherwise use rich refusals as an oracle. The agent hears *that action is
not supported by your request*; the trace keeps the reason codes and the evidence span.

## Known limitations

- **Tool-use integrity drops.** TUI 0.937 public, 0.875 validation, against the
  baseline's 1.000. Containment lets injected *reads* execute; we stop the flow at the
  sink instead. In a domain where reading were itself the harm this trade would be wrong.
- **Single-signal ablation shows no degradation.** The signals are redundant — removing
  any one leaves ASR at 0.000. Group ablations are the informative ones; `run_matrix.ps1`
  includes the whole-custody-judge ablation for that reason.
- **Mandate support is lexical.** It asks whether trusted context contains an argument's
  value. A goal paraphrased away from the identifiers it licenses would lower support and
  over-escalate; an attacker phrasing an injection using only entities the goal already
  names would raise it.
- **Counterfactual replay is not implemented.** Stage 2 of the design doc needs to
  re-plan with content masked, which requires a model the defense boundary does not
  provide. See `docs/not-built.md`.
- **No internal model signals.** Attention and hidden-state probes need the agent's
  forward pass. Over `--defense-url` the defense never sees it.
- **Numbers in the table above are from the mock model.** Qwen3-8B results for the original pipeline and for Guardyn-Flow are in the section at the top.
- **Humans stay in the loop** for every consequential action without a recorded
  confirmation, and an action attributable to untrusted content is never laundered by
  routing it past a human — `request_confirmation` gets no risk discount when injection
  signals are live.

## Running it

    uv venv
    uv pip install -r requirements.txt
    uv pip install pytest httpx2          # tests only
    .venv\Scripts\python -m pytest tests -q
    $env:SENTINEL_TRACE = "observability\decisions.jsonl"
    .venv\Scripts\python -m uvicorn app.main:app --port 8080

From the starter-kit checkout, in a second terminal:

    uv run sentinel run --scenario scenarios/validation/enterprise_val_encoded_exfil.yaml --defense-url http://127.0.0.1:8080
    uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json

Evidence loop and calibration:

    .\run_matrix.ps1 -Kit C:\dev\Sentinel_Starter_Kit
    .venv\Scripts\python tools\calibrate.py observability\decisions.jsonl --alpha 0.05

Ledger:

    cd observability; python -m http.server 8090     # then visit localhost:8090
