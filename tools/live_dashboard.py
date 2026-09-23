"""Local live-testing orchestrator for the Guardyn dashboard.

Separate from the decision endpoint (app/main.py) and the read-only evidence server. It selects
an official scenario, runs fresh baseline-then-protected pairs one at a time, owns and cancels
only its own child processes, and serves persisted, scrubbed evidence through a resumable cursor.

    python tools/live_dashboard.py --kit ../Sentinel_Starter_Kit

Run it with the kit's environment (it needs both Sentinel and Guardyn dependencies). It binds to
127.0.0.1 only; remote or multi-user deployment is out of scope.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.live_events import Scrubber, explain_step, now_iso  # noqa: E402

DEFAULT_QWEN_TAG = "qwen3.5:9b"
ENGINE_ORDER = ("qwen", "mock")
# One curated story per domain. A label for navigation only; never an input to a decision.
FEATURED = {"enterprise": "enterprise_poisoned_invoice", "finance": "finance_false_approval",
            "soc": "soc_hostile_log_text"}
TERMINAL = {"completed", "failed", "cancelled", "interrupted", "skipped"}
RUN_TIMEOUT_S = {"mock": 300, "qwen": 2400}
MAX_NEW_TOKENS = 768
ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "OLLAMA_HOST")


class Busy(RuntimeError):
    def __init__(self, active: str) -> None:
        super().__init__("another live job is active")
        self.active = active


class Unavailable(RuntimeError):
    pass


def _utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _alive(pid: int) -> bool:
    if os.name == "nt":  # os.kill(pid, 0) would send CTRL_C_EVENT on Windows, not probe the process
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    return True


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def read_events(path: Path, after: int = -1, limit: int = 500) -> tuple[list[dict], bool]:
    """Complete lines only; a partially written tail stays on disk until it is finished."""
    if not path.is_file():
        return [], False
    data = path.read_bytes()
    lines = data.split(b"\n")
    pending_tail = bool(lines[-1].strip())
    out = []
    for raw in lines[:-1]:
        if not raw.strip():
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if event.get("seq", -1) > after:
            out.append(event)
    out.sort(key=lambda e: e["seq"])
    return out[:limit], pending_tail


class Orchestrator:
    def __init__(self, kit: Path, runs_dir: Path, python: str = sys.executable, ollama_host: str | None = None,
                 launcher=None, catalog: list[dict] | None = None, qwen_tag: str = DEFAULT_QWEN_TAG) -> None:
        self.kit, self.runs_dir, self.python = kit.resolve(), runs_dir.resolve(), python
        self.qwen_tag = qwen_tag
        self.engines = {"qwen": f"ollama:{qwen_tag}", "mock": "mock"}
        host = ollama_host or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        self.ollama = host if host.startswith("http") else "http://" + host
        self.lock = threading.RLock()
        self.jobs: dict[str, dict] = {}
        self.idempotency: dict[str, str] = {}
        self.active: str | None = None
        self.launcher = launcher or self._execute_run
        self._catalog = catalog
        self._scrubbers: dict[str, Scrubber] = {}
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self._reconcile()

    # ---- persistence ------------------------------------------------------------------------
    def _save(self, job: dict) -> None:
        path = self.runs_dir / job["job_id"] / "job.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(job, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    def _reconcile(self) -> None:
        """After a restart: never relaunch; mark unfinished work interrupted and flag live owned pids."""
        for path in sorted(self.runs_dir.glob("*/job.json")):
            try:
                job = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            changed = False
            for run in job["runs"]:
                if run["state"] not in TERMINAL:
                    run["state"], changed = "interrupted", True
                    alive = [pid for pid in run.get("pids", []) if _alive(pid)]
                    run["detail"] = ("orchestrator restarted during this run; owned process(es) still alive, "
                                     "cleanup unresolved" if alive else "orchestrator restarted during this run")
            if job["state"] not in TERMINAL:
                job["state"], changed = "interrupted", True
            self.jobs[job["job_id"]] = job
            if job.get("idempotency_key"):
                self.idempotency[job["idempotency_key"]] = job["job_id"]
            if changed:
                self._save(job)

    # ---- catalog / preflight ----------------------------------------------------------------
    def _kit_imports(self):
        if str(self.kit / "src") not in sys.path:
            sys.path.insert(0, str(self.kit / "src"))

    def catalog(self) -> list[dict]:
        if self._catalog is None:
            self._kit_imports()
            from sentinel.evaluator.runner import load_suite
            items = []
            for split in ("public", "validation"):
                for s in load_suite(self.kit / "scenarios" / split):
                    items.append({
                        "id": s.id, "split": s.split.value, "domain": s.domain.value, "title": s.title,
                        "description": s.description, "tags": list(s.tags), "attack_present": s.attack.present,
                        "attack_family": s.attack.family.value if s.attack.present else None,
                        "max_steps": s.max_steps, "seed": s.seed,
                        "featured": FEATURED.get(s.domain.value) == s.id,
                    })
            self._catalog = sorted(items, key=lambda i: (i["domain"], i["split"], i["id"]))
        return self._catalog

    def scenario(self, scenario_id: str) -> dict | None:
        return next((s for s in self.catalog() if s["id"] == scenario_id), None)

    def scrubber(self, scenario_id: str) -> Scrubber:
        """Protected values are recomputed in memory from the official fixture; never persisted."""
        if scenario_id not in self._scrubbers:
            try:
                self._kit_imports()
                from sentinel.config import load_competition
                from sentinel.core.state import WorldState
                from sentinel.evaluator.runner import load_suite
                split = self.scenario(scenario_id)["split"]
                scenario = next(s for s in load_suite(self.kit / "scenarios" / split) if s.id == scenario_id)
                state = WorldState.from_scenario(scenario, self.kit, load_competition(None, self.kit).run_seed)
                self._scrubbers[scenario_id] = Scrubber({c.name: c.value for c in state.canaries})
            except Exception:
                self._scrubbers[scenario_id] = Scrubber()  # generic shapes are still redacted
        return self._scrubbers[scenario_id]

    def kit_commit(self) -> str | None:
        try:
            return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.kit, text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    def qwen_status(self) -> dict:
        import httpx
        try:
            response = httpx.get(self.ollama + "/api/tags", timeout=2)
            response.raise_for_status()
            models = response.json().get("models", [])
        except Exception as exc:
            return {"available": False, "tag": self.qwen_tag, "detail": f"Ollama not reachable at {self.ollama} ({type(exc).__name__})"}
        match = [m for m in models if m.get("name") == self.qwen_tag]
        if len(match) != 1:
            return {"available": False, "tag": self.qwen_tag, "detail": f"model tag {self.qwen_tag} is not installed; no substitute is used"}
        return {"available": True, "tag": self.qwen_tag, "digest": match[0].get("digest"), "detail": "installed"}

    def preflight(self) -> dict:
        return {
            "kit": {"ok": (self.kit / "src" / "sentinel" / "cli.py").is_file(), "commit": self.kit_commit()},
            "engines": {"mock": {"available": True, "detail": "fixture-driven mock model; uses the evaluator's "
                                 "reference plan; LLM judge off", "reference_plan": True, "judge": False},
                        "qwen": {**self.qwen_status(), "reference_plan": False, "judge": True}},
            "artifacts_writable": os.access(self.runs_dir, os.W_OK),
            "active_job": self.active,
        }

    # ---- jobs -------------------------------------------------------------------------------
    def launch(self, scenario_id: str, engines: list[str], idempotency_key: str) -> dict:
        scenario = self.scenario(scenario_id)
        if scenario is None:
            raise ValueError("unknown scenario id")
        chosen = [e for e in ENGINE_ORDER if e in set(engines)]
        if not chosen or len(set(engines)) != len(engines) or not set(engines) <= set(self.engines):
            raise ValueError("engines must be a non-empty subset of qwen, mock")
        if not idempotency_key or len(idempotency_key) > 80:
            raise ValueError("idempotency key required")
        with self.lock:
            if idempotency_key in self.idempotency:
                return self.jobs[self.idempotency[idempotency_key]]
            if self.active is not None:
                raise Busy(self.active)
            digest = None
            if "qwen" in chosen:
                status = self.qwen_status()
                if not status["available"]:
                    raise Unavailable(status["detail"])
                digest = status["digest"]
            job_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
            job = {
                "job_id": job_id, "idempotency_key": idempotency_key, "scenario_id": scenario_id,
                "domain": scenario["domain"], "engines": chosen, "created_at": _utc(), "state": "queued",
                "cancel_requested": False, "mode": "live",
                "pair_config": {"kit_commit": self.kit_commit(), "scenario_seed": scenario["seed"],
                                "attacker": "static", "attack_mode": "static", "max_new_tokens": MAX_NEW_TOKENS,
                                "max_steps": scenario["max_steps"], "qwen_digest": digest,
                                "guardyn_source_digest": source_digest()},
                "runs": [
                    {"key": f"{engine}-{prot}", "engine": engine, "model": self.engines[engine],
                     "protection": "off" if prot == "baseline" else "on", "state": "queued",
                     "started_at": None, "ended_at": None, "detail": None, "pids": []}
                    for engine in chosen for prot in ("baseline", "protected")
                ],
            }
            (self.runs_dir / job_id).mkdir()
            self._save(job)
            self.jobs[job_id] = job
            self.idempotency[idempotency_key] = job_id
            self.active = job_id
        threading.Thread(target=self._run_job, args=(job,), daemon=True, name=f"job-{job_id}").start()
        return job

    def cancel(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            if job["state"] not in TERMINAL:
                job["cancel_requested"] = True
                job["state"] = "cancel-requested"
                self._save(job)
            return job

    def _run_job(self, job: dict) -> None:
        try:
            with self.lock:
                if not job["cancel_requested"]:
                    job["state"] = "running"
                self._save(job)
            for run in job["runs"]:
                with self.lock:
                    if job["cancel_requested"]:
                        run["state"], run["detail"] = "skipped", "not started: cancellation requested"
                        self._save(job)
                        continue
                    run["state"], run["started_at"] = "preparing", _utc()
                    self._save(job)
                try:
                    self.launcher(job, run)
                except Exception as exc:
                    with self.lock:
                        run["state"], run["detail"] = "failed", f"runner error: {type(exc).__name__}: {exc}"[:300]
                finally:
                    with self.lock:
                        run["ended_at"] = run["ended_at"] or _utc()
                        self._save(job)
            with self.lock:
                states = {r["state"] for r in job["runs"]}
                if job["cancel_requested"]:
                    job["state"] = "cancelled"
                elif "failed" in states or "interrupted" in states:
                    job["state"] = "failed"
                else:
                    job["state"] = "completed"  # evaluations ended; says nothing about task or attack outcome
                job["pair_complete"] = all(r["state"] == "completed" for r in job["runs"])
                self._save(job)
        finally:
            with self.lock:
                if self.active == job["job_id"]:
                    self.active = None

    # ---- one run ----------------------------------------------------------------------------
    def run_dir(self, job: dict, run: dict) -> Path:
        return self.runs_dir / job["job_id"] / run["key"]

    def _env(self, extra: dict) -> dict:
        env = {k: os.environ[k] for k in ENV_PASSTHROUGH if k in os.environ}
        env.update(PYTHONUTF8="1", PYTHONUNBUFFERED="1", OLLAMA_HOST=self.ollama, **extra)
        return env

    def _spawn(self, run: dict, cmd: list[str], cwd: Path, env: dict, log: Path) -> subprocess.Popen:
        handle = log.open("w", encoding="utf-8")
        kwargs = {"start_new_session": True} if os.name == "posix" else {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT, **kwargs)
        handle.close()
        with self.lock:
            run["pids"].append(process.pid)
        return process

    @staticmethod
    def _stop(process: subprocess.Popen | None, grace: float = 8.0) -> bool:
        """Terminate an owned process group; returns False if it could not be confirmed stopped."""
        if process is None or process.poll() is not None:
            return True
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=grace)
        except (subprocess.TimeoutExpired, ProcessLookupError):
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=grace)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                return process.poll() is not None
        return True

    def _append_runner_event(self, job: dict, run: dict, type_: str, payload: dict) -> None:
        """Only after the child has exited: seal any torn tail, then append a runner event."""
        path = self.run_dir(job, run) / "events.jsonl"
        data = path.read_bytes() if path.is_file() else b""
        if data and not data.endswith(b"\n"):
            cut = data.rfind(b"\n") + 1
            (path.parent / "events.incomplete-tail").write_bytes(data[cut:])
            data = data[:cut]
            path.write_bytes(data)
            payload = {**payload, "incomplete_tail_retained": True}
        events, _ = read_events(path)
        seq = events[-1]["seq"] + 1 if events else 0
        event = {"schema": "guardyn.live/1", "event_id": f"{run['key']}:{seq}", "seq": seq, "job_id": job["job_id"],
                 "run_key": run["key"], "type": type_, "producer": "orchestrator", "step": None,
                 "observed_at": now_iso(), "source_ts": None, "source_event_id": None, "engine": run["engine"],
                 "protection": run["protection"], "payload": payload}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def _cancelled(self, job: dict) -> bool:
        with self.lock:
            return job["cancel_requested"]

    def _execute_run(self, job: dict, run: dict) -> None:
        import httpx
        out = self.run_dir(job, run)
        out.mkdir()
        judge = run["engine"] == "qwen" and run["protection"] == "on"
        manifest = {
            "job_id": job["job_id"], "run_key": run["key"], "scenario_id": job["scenario_id"],
            "engine": run["engine"], "model": run["model"], "protection": run["protection"],
            "include_reference_plan": run["model"] == "mock", "guardyn_llm_judge": judge,
            "judge_model": self.qwen_tag if judge else None, "created_at": _utc(), **job["pair_config"],
            "note": "Fresh sandbox run with the official agent, model adapter, tools, parser and graders. "
                    "Baseline uses the kit's allow_all control (protection off). One run is not a rate.",
        }
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        server = child = None
        stopped_cleanly = True
        try:
            defense_url = None
            if run["protection"] == "on":
                port = _free_port()
                env = self._env({"SENTINEL_TRACE": str(out / "defense.jsonl"), "GUARDYN_MODE": "flow",
                                 "GUARDYN_LLM": "on" if judge else "off", "GUARDYN_DISABLE": "",
                                 "SENTINEL_ABLATE": "", "GUARDYN_CAPTURE": "", "GUARDYN_LLM_BUDGET_S": "2.5",
                                 "GUARDYN_JUDGE_MODEL": self.qwen_tag})
                server = self._spawn(run, [self.python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                                           "--port", str(port)], ROOT, env, out / "server.log")
                defense_url = f"http://127.0.0.1:{port}"
                deadline = time.monotonic() + 25
                while True:
                    if self._cancelled(job):
                        return self._finish_cancelled(job, run)
                    if server.poll() is not None:
                        raise RuntimeError("owned Guardyn server exited during startup; see server.log")
                    try:
                        if httpx.get(defense_url + "/healthz", timeout=1).status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError("owned Guardyn server did not become ready")
                    time.sleep(0.2)
            cmd = [self.python, str(ROOT / "tools" / "live_child.py"), "--kit", str(self.kit),
                   "--scenario-id", job["scenario_id"], "--model", run["model"], "--protection", run["protection"],
                   "--engine", run["engine"], "--job-id", job["job_id"], "--run-key", run["key"], "--out", str(out),
                   "--max-new-tokens", str(MAX_NEW_TOKENS)]
            if defense_url:
                cmd += ["--defense-url", defense_url]
            child = self._spawn(run, cmd, self.kit, self._env({}), out / "child.log")
            with self.lock:
                run["state"] = "running"
                self._save(job)
            deadline = time.monotonic() + RUN_TIMEOUT_S[run["engine"]]
            while child.poll() is None:
                if self._cancelled(job):
                    with self.lock:
                        run["state"] = "cancel-requested"
                        self._save(job)
                    stopped_cleanly = self._stop(child)
                    return self._finish_cancelled(job, run, stopped_cleanly)
                if time.monotonic() > deadline:
                    stopped_cleanly = self._stop(child)
                    self._append_runner_event(job, run, "run_error", {"message": "run exceeded its time limit"})
                    with self.lock:
                        run["state"], run["detail"] = "failed", "timeout"
                    return None
                time.sleep(0.2)
            with self.lock:
                run["state"] = "finalizing"
                self._save(job)
            events, _ = read_events(out / "events.jsonl", limit=10**9)
            last = events[-1]["type"] if events else None
            reconciliation = reconcile(out, events)
            with self.lock:
                run["reconciliation"] = reconciliation
                if last == "run_finished" and child.returncode == 0:
                    run["state"] = "completed"
                else:
                    run["state"] = "failed"
                    run["detail"] = f"child exited {child.returncode}; last event {last}"
            if last not in ("run_finished", "run_error"):
                self._append_runner_event(job, run, "run_error", {"message": f"runner exited {child.returncode} "
                                                                  "without a final event"})
        finally:
            ok = self._stop(child) and self._stop(server, grace=5)
            if not (ok and stopped_cleanly):
                with self.lock:
                    run["detail"] = ((run.get("detail") or "") + "; owned process cleanup unresolved").strip("; ")
            with self.lock:
                run["ended_at"] = _utc()

    def _finish_cancelled(self, job: dict, run: dict, stopped: bool = True) -> None:
        self._append_runner_event(job, run, "run_cancelled", {
            "note": "Cancelled by the operator. Sandbox actions already completed are not rolled back.",
            "owned_processes_stopped": stopped})
        with self.lock:
            run["state"] = "cancelled"

    # ---- evidence ---------------------------------------------------------------------------
    def find(self, job_id: str, run_key: str) -> tuple[dict, dict]:
        job = self.jobs.get(job_id)
        run = next((r for r in (job or {}).get("runs", []) if r["key"] == run_key), None)
        if job is None or run is None:
            raise KeyError(f"{job_id}/{run_key}")
        return job, run

    def events(self, job_id: str, run_key: str, after: int, limit: int) -> dict:
        job, run = self.find(job_id, run_key)
        events, pending = read_events(self.run_dir(job, run) / "events.jsonl", after, limit)
        return {"events": events, "state": run["state"], "pending_tail": pending,
                "job_state": job["state"], "cursor": events[-1]["seq"] if events else after}

    def defense_rows(self, job_id: str, run_key: str) -> list[dict]:
        """Guardyn's own trace for the run, reduced to structured reasons and rescrubbed."""
        job, run = self.find(job_id, run_key)
        path = self.run_dir(job, run) / "defense.jsonl"
        if run["protection"] != "on" or not path.is_file():
            return []
        scrub = self.scrubber(job["scenario_id"])
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append(scrub.value({
                "step_id": row.get("step_id"), "decision": row.get("decision"),
                "explanation": row.get("explanation"), "reason_codes": row.get("reason_codes"),
                "ladder": row.get("ladder"), "policy": row.get("policy"),
                "flags": [{k: f.get(k) for k in ("code", "family", "layer", "severity")} for f in row.get("flags") or []],
                "enforcement": row.get("enforcement"), "rewritten_action": row.get("rewritten_action"),
                "layers": row.get("layers"), "judge_model": row.get("judge_model"),
                "latency_ms": row.get("latency_ms"), "risk": row.get("risk"),
            }))
        return rows

    def explain(self, job_id: str, run_key: str, step: int, upto: int | None = None) -> dict:
        """`upto` limits the evidence to what the viewer has been shown (paused or replaying)."""
        job, run = self.find(job_id, run_key)
        events, _ = read_events(self.run_dir(job, run) / "events.jsonl", limit=10**9)
        state = run["state"]
        if upto is not None and events and upto < events[-1]["seq"]:
            events, state = [e for e in events if e["seq"] <= upto], "running"
        step_events = [e for e in events if e.get("step") == step]
        row = next((r for r in self.defense_rows(job_id, run_key) if r.get("step_id") == step), None)
        return {"step": step, "sentence": explain_step(step_events, row, state)}


def reconcile(out: Path, events: list[dict]) -> dict:
    """Compare the incremental stream with the kit's final artifact; discrepancies are surfaced, not fixed."""
    finals = list((out / "simulator").glob("*/*.jsonl"))
    if len(finals) != 1:
        return {"status": "unavailable", "detail": f"expected one final simulator artifact, found {len(finals)}"}
    final_ids = [json.loads(line)["event_id"] for line in finals[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    published = {e.get("source_event_id") for e in events if e.get("source_event_id")}
    missing = [i for i in final_ids if i not in published]
    extra = sorted(published - set(final_ids))
    return {"status": "consistent" if not missing and not extra else "discrepancy",
            "final_events": len(final_ids), "published_from_kit": len(published),
            "missing_from_stream": missing[:20], "not_in_final_artifact": extra[:20]}


def source_digest() -> str:
    sources = sorted(p for folder in ("app", "policies") for p in (ROOT / folder).rglob("*")
                     if p.suffix in (".py", ".yaml"))
    return hashlib.sha256(b"".join(p.relative_to(ROOT).as_posix().encode() + p.read_bytes() for p in sources)).hexdigest()


def create_app(orch: Orchestrator, port: int):
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel, Field

    token = secrets.token_urlsafe(24)
    origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    csp = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
           "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:")

    def guard(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            raise HTTPException(403, "cross-origin request refused")
        if not hmac.compare_digest(request.headers.get("x-guardyn-session", ""), token):
            raise HTTPException(403, "missing or invalid session token")

    class Launch(BaseModel):
        scenario_id: str = Field(max_length=120)
        engines: list[str] = Field(max_length=2)
        idempotency_key: str = Field(max_length=80)

    @app.get("/", response_class=HTMLResponse)
    def page():
        html = (ROOT / "observability" / "live.html").read_text(encoding="utf-8")
        return HTMLResponse(html.replace("__GUARDYN_SESSION__", token),
                            headers={"Content-Security-Policy": csp, "Cache-Control": "no-store"})

    @app.get("/api/catalog")
    def catalog():
        return orch.catalog()

    @app.get("/api/preflight")
    def preflight():
        return orch.preflight()

    @app.get("/api/jobs")
    def jobs():
        with orch.lock:
            return sorted(orch.jobs.values(), key=lambda j: j["created_at"], reverse=True)

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        with orch.lock:
            if job_id not in orch.jobs:
                raise HTTPException(404)
            return orch.jobs[job_id]

    @app.post("/api/jobs")
    def launch(body: Launch, request: Request):
        guard(request)
        try:
            return orch.launch(body.scenario_id, body.engines, body.idempotency_key)
        except Busy as exc:
            return JSONResponse({"detail": "a live job is already active", "active_job": exc.active}, 409)
        except Unavailable as exc:
            return JSONResponse({"detail": str(exc)}, 503)
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel(job_id: str, request: Request):
        guard(request)
        try:
            return orch.cancel(job_id)
        except KeyError:
            raise HTTPException(404)

    @app.get("/api/jobs/{job_id}/runs/{run_key}/events")
    def events(job_id: str, run_key: str, after: int = -1, limit: int = 500):
        try:
            return orch.events(job_id, run_key, after, max(1, min(limit, 2000)))
        except KeyError:
            raise HTTPException(404)

    @app.get("/api/jobs/{job_id}/runs/{run_key}/defense")
    def defense(job_id: str, run_key: str):
        try:
            return orch.defense_rows(job_id, run_key)
        except KeyError:
            raise HTTPException(404)

    @app.get("/api/jobs/{job_id}/runs/{run_key}/explain")
    def explain(job_id: str, run_key: str, step: int, upto: int | None = None):
        try:
            return orch.explain(job_id, run_key, step, upto)
        except KeyError:
            raise HTTPException(404)

    @app.get("/api/jobs/{job_id}/runs/{run_key}/manifest")
    def manifest(job_id: str, run_key: str):
        try:
            job_, run = orch.find(job_id, run_key)
        except KeyError:
            raise HTTPException(404)
        path = orch.run_dir(job_, run) / "manifest.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--runs", type=Path, default=ROOT / "observability" / "live_runs")
    parser.add_argument("--bind", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1",
                        help="dashboard listen address; use 0.0.0.0 only inside a localhost-published container")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--qwen-tag", default=DEFAULT_QWEN_TAG, help="exact Ollama tag for the Qwen engine and judge")
    args = parser.parse_args()
    if not (args.kit / "src" / "sentinel" / "cli.py").is_file():
        raise SystemExit("Not an official Sentinel checkout")
    lock = args.runs.resolve() / ".orchestrator.pid"
    args.runs.mkdir(parents=True, exist_ok=True)
    if lock.exists():
        try:
            other = int(lock.read_text().strip())
        except ValueError:
            other = 0
        if other and other != os.getpid() and _alive(other):
            raise SystemExit(f"Another orchestrator (pid {other}) owns {args.runs}; one live runner at a time.")
    lock.write_text(str(os.getpid()))
    import uvicorn
    try:
        uvicorn.run(create_app(Orchestrator(args.kit, args.runs, qwen_tag=args.qwen_tag), args.port),
                    host=args.bind, port=args.port)
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
