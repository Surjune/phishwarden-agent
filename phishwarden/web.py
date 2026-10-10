"""PhishWarden dashboard server.

Run: uv run python -m phishwarden.web   →   http://localhost:8600
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from phishwarden import config, narrate, seed

WEB_DIR = Path(__file__).parent / "web"
UI_HOST = "127.0.0.1"
UI_PORT = int(os.getenv("PHISHWARDEN_UI_PORT", "8600"))
HEALTH_TIMEOUT = httpx.Timeout(1.5)
AGNTID_RUNTIME_HEALTH = os.getenv("AGNTID_RUNTIME_HEALTH", "http://127.0.0.1:8080/health")

RUN_ENDPOINTS = {
    "before": (config.DIRECT_MCP_URL, config.DIRECT_MCP_URL),
    "after": (config.AGNTID_TRIAGE_MCP_URL, config.AGNTID_RESPONSE_MCP_URL),
}

_processes: dict[str, subprocess.Popen[bytes]] = {}


def _running(label: str) -> bool:
    proc = _processes.get(label)
    return proc is not None and proc.poll() is None


def _failed(label: str) -> bool:
    proc = _processes.get(label)
    return proc is not None and proc.poll() not in (None, 0)


def _label(request: Request) -> str | None:
    label = request.path_params["label"]
    return label if label in narrate.LABELS else None


async def index(_: Request) -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


async def email(_: Request) -> JSONResponse:
    return JSONResponse(narrate.reported_email())


async def run_state(request: Request) -> JSONResponse:
    label = _label(request)
    if label is None:
        return JSONResponse({"error": "unknown run"}, status_code=404)
    data = narrate.narrate_run(label)
    data["running"] = _running(label)
    data["failed"] = _failed(label)
    data["available"] = bool(RUN_ENDPOINTS[label][0])
    return JSONResponse(data)


async def start_run(request: Request) -> JSONResponse:
    label = _label(request)
    if label is None:
        return JSONResponse({"error": "unknown run"}, status_code=404)
    if any(_running(name) for name in narrate.LABELS):
        return JSONResponse({"error": "A run is already in progress."}, status_code=409)
    triage_url, response_url = RUN_ENDPOINTS[label]
    if not triage_url:
        return JSONResponse({"error": "AgntID proxy URL is not configured."}, status_code=400)
    await asyncio.to_thread(seed.seed)
    config.RUNS_DIR.mkdir(exist_ok=True)
    (config.RUNS_DIR / f"{label}.jsonl").write_text("", encoding="utf-8")
    env = {**os.environ, "TRIAGE_MCP_URL": triage_url, "RESPONSE_MCP_URL": response_url, "PYTHONIOENCODING": "utf-8"}
    stderr_log = (config.RUNS_DIR / f"{label}.stderr.log").open("wb")
    _processes[label] = subprocess.Popen(
        [sys.executable, "-m", "phishwarden.agent", "--label", label],
        cwd=config.ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=stderr_log,
    )
    return JSONResponse({"started": label})


async def reset(_: Request) -> JSONResponse:
    if any(_running(name) for name in narrate.LABELS):
        return JSONResponse({"error": "Wait for the current run to finish."}, status_code=409)
    count = await asyncio.to_thread(seed.seed)
    return JSONResponse({"messages": count})


async def compare(_: Request) -> JSONResponse:
    return JSONResponse(narrate.compare())


async def _probe(client: httpx.AsyncClient, method: str, url: str, ok: set[int] | None = None) -> bool:
    try:
        response = await client.request(method, url)
    except httpx.HTTPError:
        return False
    return response.status_code in ok if ok else True


async def health(_: Request) -> JSONResponse:
    async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT) as client:
        mail, tools, agntid = await asyncio.gather(
            _probe(client, "GET", f"{config.MAILPIT_API}/info", {200}),
            _probe(client, "GET", config.DIRECT_MCP_URL),  # any HTTP answer means the server is up
            _probe(client, "GET", AGNTID_RUNTIME_HEALTH, {200}),
        )
    return JSONResponse({"mail": mail, "tools": tools, "agntid": agntid, "agntid_configured": bool(config.AGNTID_TRIAGE_MCP_URL)})


app = Starlette(
    routes=[
        Route("/", index),
        Route("/api/email", email),
        Route("/api/runs/{label}", run_state),
        Route("/api/runs/{label}/start", start_run, methods=["POST"]),
        Route("/api/reset", reset, methods=["POST"]),
        Route("/api/compare", compare),
        Route("/api/health", health),
    ]
)


if __name__ == "__main__":
    print(f"PhishWarden dashboard: http://localhost:{UI_PORT}")
    uvicorn.run(app, host=UI_HOST, port=UI_PORT, log_level="warning")
