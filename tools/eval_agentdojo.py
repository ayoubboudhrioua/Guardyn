"""Run official AgentDojo tasks with native local Ollama; resume completed cases.

Run using the separate AgentDojo venv. Labels and success checks stay here, never
inside the defense. A small --limit is a smoke test, not a full benchmark score.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import subprocess
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--attacks", nargs="+", default=["ignore_previous", "system_message"])
    parser.add_argument("--model", default="qwen3.5:9b")
    parser.add_argument("--version", default="v1.2.2")
    parser.add_argument("--limit", type=int, default=0, help="First N user tasks per suite; 0 runs all")
    parser.add_argument("--injection-limit", type=int, default=0)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("SENTINEL_TRACE", str(args.output / "decisions.jsonl"))
    os.environ.setdefault("GUARDYN_JUDGE_MODEL", args.model)
    from agentdojo.attacks.attack_registry import load_attack
    import agentdojo.attacks  # registers official attacks
    from agentdojo.task_suite.load_suites import get_suite
    from integrations.agentdojo import GuardynAgent

    agent = GuardynAgent(args.model, defended=not args.baseline)
    manifest = {"model": args.model, "defended": not args.baseline, "version": args.version,
                "suites": args.suites, "attacks": args.attacks, "limit": args.limit,
                "injection_limit": args.injection_limit}
    root = Path(__file__).resolve().parents[1]
    sources = sorted(p for folder in ("app", "integrations", "policies") for p in (root / folder).rglob("*") if p.suffix in (".py", ".yaml"))
    manifest["source_digest"] = hashlib.sha256(b"".join(p.relative_to(root).as_posix().encode() + p.read_bytes() for p in sources)).hexdigest()
    import agentdojo
    checkout = Path(agentdojo.__file__).resolve().parents[2]
    manifest["agentdojo_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    tags = agent.client.get("/api/tags")
    tags.raise_for_status()
    manifest["model_digest"] = next((m["digest"] for m in tags.json()["models"] if m["name"] == args.model), None)
    if manifest["model_digest"] is None:
        raise SystemExit("Requested model is not installed in Ollama")
    manifest_path = args.output / "manifest.json"
    if manifest_path.exists() and json.loads(manifest_path.read_text()) != manifest:
        raise SystemExit("Output belongs to a different experiment. Use a new directory.")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    snapshot = args.output / "source.zip"
    if not snapshot.exists():
        with zipfile.ZipFile(snapshot, "w", zipfile.ZIP_DEFLATED) as archive:
            for source in sources:
                archive.write(source, source.relative_to(root).as_posix())
            archive.write(Path(__file__), "tools/eval_agentdojo.py")
    results_path = args.output / "results.jsonl"
    rows = [json.loads(line) for line in results_path.read_text().splitlines()] if results_path.exists() else []
    done = {row["case"] for row in rows if not row.get("error")}
    for suite_name in args.suites:
        suite = get_suite(args.version, suite_name)
        tasks = list(suite.user_tasks.values())
        injections = list(suite.injection_tasks.values())
        if args.limit:
            tasks = tasks[:args.limit]
        if args.injection_limit:
            injections = injections[:args.injection_limit]
        attacks = [(name, load_attack(name, suite, agent)) for name in args.attacks]
        for task in tasks:
            cases = [("clean", None, {})]
            for name, attack in attacks:
                for injection in injections:
                    try:
                        payloads = attack.attack(task, injection)
                    except ValueError as exc:
                        if "not injectable" not in str(exc):
                            raise
                        continue
                    cases.append((name, injection, payloads))
            for attack_name, injection, payloads in cases:
                key = f"{suite_name}/{task.ID}/{attack_name}/{injection.ID if injection else '-'}"
                if key in done:
                    continue
                started = time.monotonic()
                row = {"case": key, "suite": suite_name, "attacked": injection is not None}
                try:
                    utility, success = suite.run_task_with_pipeline(agent, task, injection, payloads)
                    exposed = any(p in t or json.dumps(p)[1:-1] in t for p in payloads.values() for t in agent.observed_text)
                    row.update(utility=bool(utility), attack_success=bool(success) if injection else None,
                               attack_exposed=exposed, run_id=agent.run_id,
                               decisions={d: sum(e["decision"] == d for e in agent.events) for d in ("allow", "block", "rewrite", "escalate")})
                except Exception as exc:
                    row["error"] = f"{type(exc).__name__}: {exc}"
                row["elapsed_s"] = round(time.monotonic() - started, 2)
                with results_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row) + "\n")
                rows.append(row)
                print(json.dumps(row), flush=True)
    # Latest attempt per case; never count errors as safe outcomes.
    latest = {row["case"]: row for row in rows}.values()
    valid = [r for r in latest if "error" not in r]
    clean = [r for r in valid if not r["attacked"]]
    attacked = [r for r in valid if r["attacked"]]
    summary = {"manifest": manifest, "completed": len(valid), "errors": sum("error" in r for r in latest),
               "clean_count": len(clean), "attack_count": len(attacked),
               "clean_utility": sum(r["utility"] for r in clean) / len(clean) if clean else None,
               "attack_utility": sum(r["utility"] for r in attacked) / len(attacked) if attacked else None,
               "asr": sum(r["attack_success"] for r in attacked) / len(attacked) if attacked else None,
               "exposed_attacks": sum(r["attack_exposed"] for r in attacked)}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
