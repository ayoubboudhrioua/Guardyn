"""Run ONE official Sentinel scenario and publish its evidence incrementally.

The official agent, model adapters, tools, parser, graders and defense client run unchanged.
This process only observes: it wraps the event log, the model's `propose` call and provenance
registration so that each boundary is persisted (scrubbed, fsynced) the moment it happens.
Baseline runs use the kit's own `allow_all` control; its "allow" is reported as
"protection off", never as a Guardyn verdict.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.live_events import SCHEMA, Scrubber, normalize_kit_event, now_iso, outcome_assessment  # noqa: E402


class Publisher:
    """Append-only, persist-before-publish canonical event file."""

    def __init__(self, path: Path, run_key: str, job_id: str, engine: str, protection: str) -> None:
        self.path, self.run_key, self.job_id = path, run_key, job_id
        self.engine, self.protection = engine, protection
        self.seq = 0
        self.lock = threading.Lock()
        self.handle = path.open("x", encoding="utf-8")

    def emit(self, type_: str, payload: dict, *, producer: str, step: int | None = None,
             source_ts: str | None = None, source_event_id: str | None = None) -> None:
        with self.lock:
            event = {
                "schema": SCHEMA, "event_id": f"{self.run_key}:{self.seq}", "seq": self.seq,
                "job_id": self.job_id, "run_key": self.run_key, "type": type_, "producer": producer,
                "step": step, "observed_at": now_iso(), "source_ts": source_ts,
                "source_event_id": source_event_id, "engine": self.engine, "protection": self.protection,
                "payload": payload,
            }
            self.handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            self.handle.flush()
            os.fsync(self.handle.fileno())
            self.seq += 1

    def close(self) -> None:
        self.handle.close()


class ObservedModel:
    """Delegates everything to the official model; announces waiting/completion around propose."""

    def __init__(self, model, publisher: Publisher, scrub_ref: dict) -> None:
        self._model, self._pub, self._scrub = model, publisher, scrub_ref

    def propose(self, context):
        step = getattr(context, "step_id", None)
        self._pub.emit("model_waiting", {}, producer="observer", step=step)
        try:
            action = self._model.propose(context)
        except Exception as exc:
            # Malformed output (ModelError) is recorded by the official agent as a model_output
            # event; only failures the agent does not record are published here.
            if type(exc).__name__ != "ModelError":
                self._pub.emit("model_error", {"message": self._scrub["s"].text(f"{type(exc).__name__}: {exc}", 300),
                                               "recoverable": False}, producer="observer", step=step)
            raise
        from tools.live_events import _action
        self._pub.emit("candidate", {"action": _action(self._scrub["s"], action.model_dump(mode="json"))},
                       producer="agent", step=step)
        return action

    def __getattr__(self, name):
        return getattr(self._model, name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--model", required=True, help="mock | ollama:<tag>")
    parser.add_argument("--protection", choices=["on", "off"], required=True)
    parser.add_argument("--defense-url")
    parser.add_argument("--engine", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--run-key", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-new-tokens", type=int, default=768)
    args = parser.parse_args()
    if (args.protection == "on") != bool(args.defense_url):
        parser.error("protected runs need --defense-url; baseline runs must not have one")

    kit = args.kit.resolve()
    sys.path.insert(0, str(kit / "src"))
    from sentinel.cli import _defense_factory
    from sentinel.config import load_competition
    from sentinel.agent import reference as reference_mod
    from sentinel.core.events import EventLog, event_to_json
    from sentinel.evaluator import runner as runner_mod
    from sentinel.evaluator.runner import AttackMode, RunConfig, eval_group_name, load_suite, run_scenario
    from sentinel.attackers.baselines import ATTACKERS
    from sentinel.storage.runs import ArtifactStore
    from tools.sentinel_suite import model_factory

    publisher = Publisher(args.out / "events.jsonl", args.run_key, args.job_id, args.engine, args.protection)
    scrub_ref = {"s": Scrubber()}
    provenance: dict[str, dict] = {}
    try:
        publisher.emit("run_started", {"engine": args.engine, "protection": args.protection, "model": args.model},
                       producer="runner")
        scenarios = [s for split in ("public", "validation") for s in load_suite(kit / "scenarios" / split)
                     if s.id == args.scenario_id]
        if len(scenarios) != 1:
            raise ValueError("scenario id is not in the official catalog")
        scenario = scenarios[0]

        # --- observation-only wrappers -------------------------------------------------------
        original_state = runner_mod.WorldState.from_scenario

        def observed_state(*a, **kw):
            state = original_state(*a, **kw)
            scrub_ref["s"] = Scrubber({c.name: c.value for c in state.canaries})
            return state

        runner_mod.WorldState.from_scenario = observed_state  # classmethod replaced by a plain wrapper

        original_register = reference_mod.ReferenceAgent._register

        def observed_register(self, items):
            ids = original_register(self, items)
            for ref, item in zip(ids, items):
                provenance[ref] = {"source_type": str(getattr(item.source_type, "value", item.source_type)),
                                   "source_id": scrub_ref["s"].text(str(item.source_id), 120),
                                   "trust_level": str(getattr(item.trust_level, "value", item.trust_level))}
            return ids

        reference_mod.ReferenceAgent._register = observed_register

        original_append = EventLog.append

        def observed_append(self, *a, **kw):
            event = original_append(self, *a, **kw)
            raw = json.loads(event_to_json(event))
            mapped = normalize_kit_event(raw, args.protection, scrub_ref["s"], provenance)
            if mapped:
                publisher.emit(mapped[0], mapped[1], producer=raw["actor"], step=raw["step_id"],
                               source_ts=raw["timestamp"], source_event_id=raw["event_id"])
            return event

        EventLog.append = observed_append

        base_factory = model_factory(args.model, False, args.max_new_tokens)
        observed_factory = lambda: ObservedModel(base_factory(), publisher, scrub_ref)  # noqa: E731

        competition = load_competition(None, kit)
        defense_factory = _defense_factory("allow_all" if args.protection == "off" else None,
                                           args.defense_url, competition)
        store = ArtifactStore(args.out / "simulator")
        instance = defense_factory()
        group = store.unique_group(eval_group_name(f"run-{scenario.id}", instance.name))
        config = RunConfig(root=kit, competition=competition, attack_mode=AttackMode.STATIC,
                           model_factory=observed_factory, include_reference_plan=args.model == "mock",
                           artifacts=store, artifact_group=group)
        try:
            # Same attacker the official suite runner uses (tools/sentinel_suite.py --attacker static).
            result = run_scenario(scenario, instance, config, ATTACKERS["static"]())
        finally:
            instance.close()
        outcome = result.outcome.model_dump(mode="json")
        assessment = outcome_assessment(outcome, scrub_ref["s"], args.protection)
        (args.out / "outcome.json").write_text(json.dumps(assessment, indent=2), encoding="utf-8")
        publisher.emit("assessment", assessment, producer="official_scorer")
        publisher.emit("run_finished", {"status": "completed"}, producer="runner")
        return 0
    except Exception as exc:  # errors stay visible; they are never counted as prevented attacks
        (args.out / "child-error.log").write_text(traceback.format_exc(), encoding="utf-8")
        publisher.emit("run_error", {"message": scrub_ref["s"].text(f"{type(exc).__name__}: {exc}", 300)},
                       producer="runner")
        return 1
    finally:
        publisher.close()


if __name__ == "__main__":
    sys.exit(main())
