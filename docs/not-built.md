# What the design doc describes that this submission does not implement

Written up rather than quietly dropped, because the report is scored on honesty.

## Stage 2 — causal authority attribution (counterfactual replay)

The design calls for re-planning with the user request masked, and again with each
provenance source masked, then reading the action off a 2×2. The defense boundary makes
this impossible as written: `POST /v1/decision` receives the conversation, provenance,
policy context and one candidate action. It does not receive the model, and it cannot
ask the agent to re-plan.

Two honest routes exist:

1. **Run our own model inside the defense service.** Load a small instruct model, feed
   it the same conversation with the untrusted span redacted, and compare the tool call
   it proposes against the candidate. This is a real implementation of MELON's idea, it
   costs an extra forward pass per consequential action, and it needs the suspicion dial
   as a gate so it only runs when cheaper signals are ambiguous.
2. **Fork the reference agent.** Gives exact replay, but the submission is then a fork
   of the simulator rather than a defense behind the published interface.

We chose neither, because three days was not enough to do either honestly. The value
passport mechanism captures the same intuition — *did this action's parameters come from
the user or from the attacker* — at a fraction of the cost, and it survives paraphrase
for the same reason counterfactual replay does: neither reads the attack's wording.

## Stage 3 — internal model signals

Attention distraction ratio and a hidden-state linear probe both require the agent's
forward pass. Over `--defense-url` the defense never sees it, so these are not
implementable behind the published interface at all. Reporting them as future work is
accurate; claiming them would not be.

## Conformal calibration, honestly sized

`tools/calibrate.py` computes a split-conformal threshold over *decisions*, not
scenarios. With 28 scenarios the scenario-level sample cannot support a 95% claim. Quote
the threshold with the n it was computed from.
