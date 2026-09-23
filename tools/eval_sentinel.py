"""Reproducible Sentinel run using the official evaluator and an owned server.

Run with the environment where Sentinel and Guardyn dependencies are installed.
The output must be a new directory: completed and failed evidence is never replaced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import zipfile

import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="ollama:qwen3:8b")
    parser.add_argument("--port", type=int, default=8084)
    parser.add_argument("--thinking", action="store_true")
    parser.add_argument("--max-new-tokens", type=int, default=768)
    parser.add_argument("--subset", choices=["all", "benign"], default="all")
    parser.add_argument("--attacker", choices=["static", "mutation"], default="static")
    parser.add_argument("--attack-mode", choices=["static", "adaptive"], default="static")
    parser.add_argument("--keep-going", action="store_true", help="Retain error results and finish other splits; still exit nonzero")
    parser.add_argument("--disable", nargs="*", choices=["L3", "L4", "L5", "BUDGET"], default=[])
    parser.add_argument("--splits", nargs="+", choices=["public", "validation"], default=["public", "validation"])
    args = parser.parse_args()
    if args.max_new_tokens < 1:
        parser.error("--max-new-tokens must be positive")
    if not args.model.startswith("ollama:") and (args.thinking or args.max_new_tokens != 768):
        parser.error("Runtime overrides require an Ollama model")
    root = Path(__file__).resolve().parents[1]
    kit, output = args.kit.resolve(), args.output.resolve()
    if output.exists():
        raise SystemExit("Output already exists. Use a new directory to preserve evidence.")
    if not (kit / "src" / "sentinel" / "cli.py").is_file():
        raise SystemExit("Not an official Sentinel checkout")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", args.port))
    model_digest = None
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    if not host.startswith("http"):
        host = "http://" + host
    if args.model.startswith("ollama:"):
        tag = args.model.split(":", 1)[1]
        response = httpx.get(host + "/api/tags")
        response.raise_for_status()
        model_digest = next((m["digest"] for m in response.json()["models"] if m["name"] == tag), None)
        if model_digest is None:
            raise SystemExit("Requested model is not installed")
    sources = sorted(p for folder in ("app", "integrations", "policies") for p in (root / folder).rglob("*")
                     if p.suffix in (".py", ".yaml"))
    digest = hashlib.sha256(b"".join(p.relative_to(root).as_posix().encode() + p.read_bytes() for p in sources)).hexdigest()
    manifest = {
        "model": args.model, "model_digest": model_digest, "source_digest": digest,
        "sentinel_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=kit, text=True).strip(),
        "splits": args.splits, "mode": "flow", "judge_enabled": args.model != "mock",
        "disabled_layers": args.disable,
        "attack_mode": args.attack_mode, "attacker": args.attacker,
        "subset": args.subset,
        "runtime": {"thinking": args.thinking, "max_new_tokens": args.max_new_tokens,
                    "max_context_chars": 12000},
        "note": "Official evaluator, agent, prompt, tools, parser and graders. Runtime settings declared; diagnostic scores are not jury scores.",
    }
    output.mkdir(parents=True)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with zipfile.ZipFile(output / "source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sources + [Path(__file__), root / "tools" / "report_sentinel.py", root / "tools" / "sentinel_suite.py"]:
            archive.write(source, source.relative_to(root).as_posix())
    env = dict(os.environ)
    env.update(SENTINEL_TRACE=str(output / "decisions.jsonl"), GUARDYN_MODE="flow",
               GUARDYN_LLM="off" if args.model == "mock" else "on", GUARDYN_DISABLE=",".join(args.disable),
               SENTINEL_ABLATE="", GUARDYN_CAPTURE="", GUARDYN_LLM_BUDGET_S="2.5")
    if args.model.startswith("ollama:"):
        env["GUARDYN_JUDGE_MODEL"] = args.model.split(":", 1)[1]
    url = f"http://127.0.0.1:{args.port}"
    with (output / "server.log").open("w", encoding="utf-8") as server_log:
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                    "--host", "127.0.0.1", "--port", str(args.port)],
                                   cwd=root, env=env, stdout=server_log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 25
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Owned defense server exited; see server.log")
                try:
                    ready = httpx.get(url + "/healthz", timeout=1)
                    if ready.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Owned defense server did not become ready")
                time.sleep(0.1)
            failed_splits = []
            for split in args.splits:
                print(json.dumps({"status": "starting", "split": split, "model": args.model}), flush=True)
                cmd = [sys.executable, str(root / "tools" / "sentinel_suite.py"), "--kit", str(kit), "--split", split,
                       "--defense-url", url, "--model", args.model,
                       "--artifacts", str(output / "simulator"), "--output", str(output / f"{split}-scorecard.json"),
                       "--max-new-tokens", str(args.max_new_tokens), "--subset", args.subset,
                       "--attacker", args.attacker, "--attack-mode", args.attack_mode]
                if args.thinking:
                    cmd.append("--thinking")
                with (output / f"{split}.log").open("w", encoding="utf-8") as log:
                    subprocess.run(cmd, cwd=kit, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
                cards = sorted((output / "simulator" / "scorecards").glob(f"eval-{split}-*.json"))
                if len(cards) != 1:
                    raise RuntimeError("Expected exactly one scorecard for the split")
                subprocess.run([sys.executable, str(root / "tools" / "report_sentinel.py"),
                                "--scorecard", str(cards[0]), "--decisions", str(output / "decisions.jsonl"),
                                "--simulator", str(output / "simulator" / cards[0].stem),
                                "--output", str(output / split)], cwd=root, check=True)
                summary = json.loads((output / split / "summary.json").read_text())
                if not summary["evaluation_complete_without_errors"]:
                    failed_splits.append(split)
                    print(json.dumps({"status": "completed_with_errors", "split": split}), flush=True)
                    if not args.keep_going:
                        break
                else:
                    print(json.dumps({"status": "completed", "split": split}), flush=True)
            if failed_splits:
                raise RuntimeError(f"Splits with model or defense errors: {failed_splits}; retained, not counted as prevented attacks")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
