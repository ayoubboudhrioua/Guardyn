# Isnad — authority-flow control for tool-using agents

SENTINEL challenge submission, IndabaX Tunisia 2026.

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
    Stage 0  Mandate Compiler  ──────────────►  Stage 1  Isnad labels (IFC)
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
| **Isnad** | public | 1.000 | 0.000 | 0.000 | **0.000** | 0.000 | 1.000 | **0.030** | **0.053** |
| `provenance` | validation | 1.000 | 0.250 | 0.111 | 0.000 | 0.000 | 0.889 | 0.060 | 0.027 |
| **Isnad** | validation | 1.000 | **0.000** | **0.000** | 0.000 | 0.000 | **1.000** | **0.022** | **0.002** |

The baseline's validation failure is `enterprise_val_encoded_exfil`: its taint matching
is verbatim and the payload is base64.

## What each idea buys, concretely

**Mandate Compiler.** The contract is built from `SYSTEM_POLICY` and
`AUTHENTICATED_USER` before anything untrusted is read. A document cannot add a tool to
it. This is what stops false-approval and forged-closure with no content analysis at all.

**Isnad labels.** Two axes, joined as weakest-trust and strongest-sensitivity. Memory
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
- **Not validated on Qwen3-8B.** All numbers above are from the deterministic mock model.
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
