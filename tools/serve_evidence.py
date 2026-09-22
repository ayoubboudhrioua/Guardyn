"""Serve an existing evidence trace read-only on localhost for review/recording."""
import argparse
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse


def create_app(trace_path: Path):
    trace_path = trace_path.resolve()
    if not trace_path.is_file():
        raise ValueError("Evidence trace does not exist")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/")
    def dashboard():
        return FileResponse(Path(__file__).resolve().parents[1] / "observability" / "index.html")

    @app.get("/v1/trace")
    def trace():
        return [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8085)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_app(args.trace), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
