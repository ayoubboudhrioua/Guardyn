"""Compare matched AgentDojo experiments without treating errors as prevention."""
import argparse
from collections import Counter
import json
from pathlib import Path


MATCHED_FIELDS = ("model", "version", "suites", "attacks", "limit", "injection_limit",
                  "source_digest", "agentdojo_commit", "model_digest")


def latest(rows):
    return {row["case"]: row for row in rows}


def summarize(baseline_manifest, defense_manifest, baseline_rows, defense_rows):
    mismatched = [field for field in MATCHED_FIELDS
                  if field not in baseline_manifest or field not in defense_manifest
                  or baseline_manifest[field] != defense_manifest[field]]
    if baseline_manifest.get("defended") is not False or defense_manifest.get("defended") is not True:
        mismatched.append("baseline/defense roles")
    if mismatched:
        raise ValueError("Experiments are not matched: " + ", ".join(mismatched))
    base, guarded = latest(baseline_rows), latest(defense_rows)
    common = sorted(base.keys() & guarded.keys())
    pairs = [(base[k], guarded[k]) for k in common if not base[k].get("error") and not guarded[k].get("error")]
    clean = [(b, d) for b, d in pairs if not b["attacked"]]
    attacks = [(b, d) for b, d in pairs if b["attacked"]]

    def counts(selected):
        return {
            "cases": len(selected),
            "baseline_task_successes": sum(b["utility"] for b, _ in selected),
            "defended_task_successes": sum(d["utility"] for _, d in selected),
            "baseline_attack_successes": sum(bool(b.get("attack_success")) for b, _ in selected),
            "defended_attack_successes": sum(bool(d.get("attack_success")) for _, d in selected),
            "baseline_exposed": sum(b.get("attack_exposed", False) for b, _ in selected),
            "defended_exposed": sum(d.get("attack_exposed", False) for _, d in selected),
            "defended_cases_with_intervention": sum(any(d.get("decisions", {}).get(k, 0) for k in ("block", "rewrite", "escalate")) for _, d in selected),
        }

    rescued = [(b, d) for b, d in attacks if b["attack_success"] and not d["attack_success"]]
    interventions = Counter(k for _, d in attacks for k, n in d.get("decisions", {}).items() for _ in range(n))
    return {
        "manifest": defense_manifest,
        "baseline_attempt_count": len(baseline_rows),
        "defense_attempt_count": len(defense_rows),
        "baseline_error_attempts": sum(bool(r.get("error")) for r in baseline_rows),
        "defense_error_attempts": sum(bool(r.get("error")) for r in defense_rows),
        "paired_valid_cases": len(pairs),
        "baseline_only_cases": sorted(base.keys() - guarded.keys()),
        "defended_only_cases": sorted(guarded.keys() - base.keys()),
        "baseline_errors": [k for k, r in base.items() if r.get("error")],
        "defense_errors": [k for k, r in guarded.items() if r.get("error")],
        "clean": counts(clean), "attacks": counts(attacks),
        "by_suite": {s: {"clean": counts([(b, d) for b, d in clean if b["suite"] == s]),
                         "attacks": counts([(b, d) for b, d in attacks if b["suite"] == s])}
                     for s in defense_manifest["suites"]},
        "baseline_success_defended_failure_cases": [b["case"] for b, _ in rescued],
        "of_those_with_observed_defense_intervention": [
            b["case"] for b, d in rescued
            if any(d.get("decisions", {}).get(k, 0) for k in ("block", "rewrite", "escalate"))],
        "defended_attack_action_decisions": dict(interventions),
        "clean_regressions": [b["case"] for b, d in clean if b["utility"] and not d["utility"]],
        "clean_improvements": [b["case"] for b, d in clean if not b["utility"] and d["utility"]],
        "note": "Matched single-run comparison, not causal proof. Model variance and exposure differ. Errors are excluded from paired valid denominators and listed separately. This panel is not the full AgentDojo benchmark.",
    }


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--defended", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = summarize(json.loads((args.baseline / "manifest.json").read_text()),
                       json.loads((args.defended / "manifest.json").read_text()),
                       read_rows(args.baseline / "results.jsonl"),
                       read_rows(args.defended / "results.jsonl"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
