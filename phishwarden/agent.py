"""PhishWarden agents: a triage agent hands off to a response agent.

Each agent talks to the SOC tools over MCP. Which MCP endpoint each agent uses — the raw
server or the AgntID runtime proxy — is the only difference between the before and after
runs. Every step is appended to runs/<label>.jsonl for the dashboard.

Usage: uv run python -m phishwarden.agent --label before
"""

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic
from mcp import Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from phishwarden import config, outcome, prompts, server

TOOL_RESULT_LOG_CHARS = 1500
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class RunLog:
    """Appends structured events to a JSONL file and echoes them to the console."""

    def __init__(self, label: str) -> None:
        config.RUNS_DIR.mkdir(exist_ok=True)
        self.path: Path = config.RUNS_DIR / f"{label}.jsonl"
        self.path.write_text("", encoding="utf-8")

    def emit(self, **event: Any) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(), **event}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        kind = event["type"]
        if kind == "tool_call":
            mark = "ERR" if event["is_error"] else "ok "
            print(f"  [{mark}] {event['agent']:<8} {event['tool']}({json.dumps(event['input'], ensure_ascii=False)})")
            if event["is_error"]:
                print(f"         -> {event['result'][:200]}")
        elif kind in ("agent_start", "agent_done", "run_start", "run_done"):
            print(f"== {kind}: {event.get('agent', '')} {event.get('mcp_url', '')}")


def _result_text(result: Any) -> str:
    parts = [getattr(block, "text", str(block)) for block in result.content]
    return "\n".join(parts) if parts else "(no content)"


async def run_agent(
    *,
    name: str,
    system: str,
    task: str,
    mcp_url: str,
    log: RunLog,
    client: anthropic.Anthropic,
) -> str:
    """Run one agent to completion and return its final text."""
    log.emit(type="agent_start", agent=name, mcp_url=mcp_url)
    transport = streamable_http_client(
        mcp_url, http_client=create_mcp_http_client(headers={"X-Agent-Id": f"phishwarden-{name}"})
    )
    async with Client(transport) as mcp:
        listed = await mcp.list_tools()
        tools = [
            {"name": t.name, "description": t.description or "", "input_schema": t.input_schema}
            for t in listed.tools
        ]
        log.emit(type="tools_listed", agent=name, tools=[t["name"] for t in tools])

        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        final_text = ""
        for _ in range(config.MAX_AGENT_TURNS):
            response = client.beta.messages.create(
                model=config.MODEL,
                max_tokens=16000,
                system=system,
                tools=tools,
                messages=messages,
                output_config={"effort": "medium"},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
            if response.stop_reason == "refusal":
                final_text = "The model declined this request."
                log.emit(type="refusal", agent=name, details=str(response.stop_details))
                break

            texts = [b.text for b in response.content if b.type == "text"]
            if texts:
                final_text = "\n".join(texts)
                log.emit(type="agent_text", agent=name, text=final_text)

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if response.stop_reason != "tool_use" or not tool_uses:
                break

            messages.append({"role": "assistant", "content": response.content})
            tool_results = []
            for block in tool_uses:
                try:
                    result = await mcp.call_tool(block.name, block.input)
                    text, is_error = _result_text(result), bool(result.is_error)
                except Exception as exc:  # transport-level failure, e.g. a proxy rejecting the call
                    text, is_error = f"{type(exc).__name__}: {exc}", True
                log.emit(
                    type="tool_call",
                    agent=name,
                    tool=block.name,
                    input=block.input,
                    is_error=is_error,
                    result=text[:TOOL_RESULT_LOG_CHARS],
                )
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": is_error}
                )
            messages.append({"role": "user", "content": tool_results})

    log.emit(type="agent_done", agent=name, final=final_text)
    return final_text


async def run_pipeline(report_id: str, label: str) -> str:
    log = RunLog(label)
    client = anthropic.Anthropic()
    log.emit(type="run_start", report_id=report_id, label=label,
             triage_mcp_url=config.TRIAGE_MCP_URL, response_mcp_url=config.RESPONSE_MCP_URL)

    triage_report = await run_agent(
        name="triage",
        system=prompts.TRIAGE_SYSTEM,
        task=prompts.triage_task(report_id),
        mcp_url=config.TRIAGE_MCP_URL,
        log=log,
        client=client,
    )
    evidence = fetch_evidence(report_id)
    final_report = await run_agent(
        name="response",
        system=prompts.RESPONSE_SYSTEM,
        task=prompts.response_task(report_id, triage_report, evidence),
        mcp_url=config.RESPONSE_MCP_URL,
        log=log,
        client=client,
    )
    log.emit(type="run_done", final_report=final_report, outcome=outcome.collect())
    return final_report


def fetch_evidence(report_id: str) -> str:
    """The reported email as the SOC case holds it, attached to the hand-off."""
    data = json.loads(server.get_report(report_id))
    return json.dumps({"headers": data["headers"], "body_text": data["body_text"]}, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PhishWarden triage and response agents.")
    parser.add_argument("--report", default="R-1042")
    parser.add_argument("--label", default="run")
    args = parser.parse_args()
    report = asyncio.run(run_pipeline(args.report, args.label))
    print("\n" + "=" * 80 + "\nFINAL INCIDENT REPORT\n" + "=" * 80 + "\n" + report)


if __name__ == "__main__":
    main()
