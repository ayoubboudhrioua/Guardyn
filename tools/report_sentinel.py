"""Join scorer outcomes and simulator execution with already-scrubbed defense evidence.

Evaluator-only IDs/labels are used for reporting, never decision-making. No raw
tool payloads are copied into the shareable dashboard artifact.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def execution_summary(events):
    """Summarize read and write outcomes without copying tool payloads."""
    return {
        "event_types": [event["type"] for event in events],
        "tools_requested": [event["payload"].get("tool") for event in events if event["type"] == "tool_request"],
        "tool_results": [{"tool": event["payload"].get("tool"), "succeeded": event["payload"].get("succeeded")}
                         for event in events if event["type"] in ("retrieval_result", "tool_result")],
        "response_emitted": any(event["type"] == "model_output" for event in events),
    }


def error_accounting(outcomes):
    model_errors = [o for o in outcomes if str(o.get("termination", "")).startswith("model_error")]
    failed = [o for o in outcomes if o in model_errors or any(d.get("defense_error") for d in o.get("decisions", []))]
    valid_attacks = [o for o in outcomes if o not in failed and o["attack_present"]]
    return {
        "evaluation_complete_without_errors": not failed,
        "model_error_scenarios": [o["scenario_id"] for o in model_errors],
        "evaluation_error_scenarios": [o["scenario_id"] for o in failed],
        "valid_attack_count": len(valid_attacks),
        "valid_attack_successes": sum(o["attack_success"] for o in valid_attacks),
        "valid_benign_count": sum(not o["attack_present"] for o in outcomes if o not in failed),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--simulator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.scorecard.read_text())
    outcomes = report["outcomes"]
    attacks = [o for o in outcomes if o["attack_present"]]
    benign = [o for o in outcomes if not o["attack_present"]]
    interventions = lambda o: [d for d in o["decisions"] if d["decision"] != "allow" and not d["legitimate"]]
    stats = {
        **error_accounting(outcomes),
        "scenarios": len(outcomes), "attacks": len(attacks),
        "successful_attacks": sum(o["attack_success"] for o in attacks),
        "attack_scenarios_with_any_intervention": sum(any(d["decision"] != "allow" for d in o["decisions"]) for o in attacks),
        "attack_scenarios_with_illegitimate_action_intervention": sum(bool(interventions(o)) for o in attacks),
        "attack_scenarios_without_illegitimate_action_intervention": sum(not interventions(o) for o in attacks),
        "illegitimate_action_decisions": dict(Counter(d["decision"] for o in attacks for d in o["decisions"] if not d["legitimate"])),
        "benign_completed": sum(o["task_success"] for o in benign), "benign_total": len(benign),
        "defense_errors": sum(bool(d.get("defense_error")) for o in outcomes for d in o["decisions"]),
        "note": "Errors are not prevented attacks. Check valid counts and error scenarios. No successful attack is not proof of a defense intervention. Composite scores are diagnostics, not jury scores.",
    }
    events = defaultdict(list)
    completed = {}
    for path in args.simulator.glob("*.jsonl"):
        for event in read_jsonl(path):
            events[(event["run_id"], event["step_id"])].append(event)
            if event["type"] == "task_success":
                completed[event["run_id"]] = event.get("payload", {})
    joined = []
    for row in read_jsonl(args.decisions):
        matches = events.get((row["run_id"], row["step_id"]))
        if not matches:
            continue
        row["execution"] = execution_summary(matches)
        row["enforcement"]["execution_observed"] = True
        joined.append(row)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    (args.output / "decisions.jsonl").write_text("".join(json.dumps(r) + "\n" for r in joined), encoding="utf-8")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
