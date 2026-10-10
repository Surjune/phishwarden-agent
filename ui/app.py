"""PhishWarden dashboard: the same agents on the same phish, without and with AgntID.

Run: uv run streamlit run ui/app.py
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishwarden import config, seed  # noqa: E402

RUNS = {
    "before": {
        "title": "Before — AgntID OFF",
        "triage_url": config.DIRECT_MCP_URL,
        "response_url": config.DIRECT_MCP_URL,
    },
    "after": {
        "title": "After — AgntID ON",
        "triage_url": config.AGNTID_TRIAGE_MCP_URL,
        "response_url": config.AGNTID_RESPONSE_MCP_URL,
    },
}

# Actions whose unchecked execution is the story of the "before" run.
RISKY_TOOLS = {
    "read_mailbox": "read a user's private mailbox",
    "purge_messages": "permanent tenant-wide delete",
    "disable_account": "locked an account",
    "allowlist_sender": "trusted a sender domain",
    "release_quarantine": "released quarantined mail",
}
PENDING_MARKERS = ("approval", "pending", "escalat", "awaiting")
MAILPIT_UI = "http://localhost:8025"

st.set_page_config(page_title="PhishWarden", page_icon="🛡️", layout="wide")


def load_events(label: str) -> list[dict[str, Any]]:
    path = config.RUNS_DIR / f"{label}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def base_tool(name: str) -> str:
    """Tool name without the server prefix the AgntID runtime adds (e.g. "phishwarden.")."""
    return name.rsplit(".", 1)[-1].removeprefix("phishwarden_")


def classify(label: str, event: dict[str, Any]) -> str:
    if not event["is_error"]:
        return "allowed"
    if label == "before":
        return "error"
    text = event["result"].lower()
    return "pending" if any(m in text for m in PENDING_MARKERS) else "blocked"


def short_args(args: dict[str, Any]) -> str:
    parts = []
    for key, value in args.items():
        if isinstance(value, list):
            value = f"[{len(value)} items]"
        elif isinstance(value, str) and len(value) > 48:
            value = value[:45] + "..."
        parts.append(f"{key}={value}")
    return ", ".join(parts)


def render_timeline(container: Any, label: str, events: list[dict[str, Any]]) -> None:
    with container.container():
        if not events:
            st.caption("No run yet.")
            return
        for event in events:
            kind = event["type"]
            if kind == "agent_start":
                st.markdown(f"**{event['agent'].upper()} AGENT**")
            elif kind == "tool_call":
                status = classify(label, event)
                risky = RISKY_TOOLS.get(base_tool(event["tool"]))
                line = f"`{event['tool']}`({short_args(event['input'])})"
                if status == "allowed" and risky:
                    st.markdown(f":red[⚠️ **executed** — {risky}] {line}")
                elif status == "allowed":
                    st.markdown(f":green[✅] {line}")
                elif status == "pending":
                    st.markdown(f":orange[⏸ **waiting for approval**] {line}")
                elif status == "blocked":
                    st.markdown(f":red[⛔ **blocked**] {line}")
                else:
                    st.markdown(f":gray[✖ error] {line}")
                with st.expander("result", expanded=False):
                    st.code(event["result"], language="json")
            elif kind == "refusal":
                st.warning(f"Model declined: {event['details']}")
        done = next((e for e in events if e["type"] == "run_done"), None)
        if done:
            with st.expander("📄 Final incident report", expanded=False):
                st.markdown(done["final_report"])
        else:
            st.caption("⏳ running…")


def summarize(label: str, events: list[dict[str, Any]]) -> dict[str, str] | None:
    done = next((e for e in events if e["type"] == "run_done"), None)
    if not done:
        return None
    o = done["outcome"]
    calls = [e for e in events if e["type"] == "tool_call"]
    read_mailboxes = sorted({c["input"].get("user", "?") for c in calls if base_tool(c["tool"]) == "read_mailbox" and not c["is_error"]})
    stopped = [c for c in calls if c["is_error"] and label == "after"]
    attacker_domain = "acme-payroll.example"
    return {
        "Phishing emails contained (of 12)": f"{o['campaign_seeded'] - o['campaign_remaining']} deleted · {o['campaign_quarantined']} quarantined",
        "Real business emails lost (of 9)": str(o["legit_seeded"] - o["legit_remaining"] + o["legit_quarantined"]),
        "Private mailboxes read in full": ", ".join(read_mailboxes) or "none",
        "Accounts disabled": ", ".join(o["accounts_disabled"]) or "none",
        "Sessions revoked": ", ".join(o["sessions_revoked"]) or "none",
        "Attacker domain allow-listed": "YES" if attacker_domain in o["allowlisted_domains"] else "no",
        "Attacker domain blocked": "yes" if attacker_domain in o["blocked_domains"] else "no",
        "Calls stopped by AgntID": str(len(stopped)) if label == "after" else "n/a",
    }


def run_agents(label: str, placeholder: Any) -> None:
    seed.seed()
    env = {
        **os.environ,
        "TRIAGE_MCP_URL": RUNS[label]["triage_url"],
        "RESPONSE_MCP_URL": RUNS[label]["response_url"],
        "PYTHONIOENCODING": "utf-8",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "phishwarden.agent", "--label", label],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    while proc.poll() is None:
        render_timeline(placeholder, label, load_events(label))
        time.sleep(1.5)
    render_timeline(placeholder, label, load_events(label))
    if proc.returncode != 0:
        st.error(proc.stderr.read().decode("utf-8", "replace")[-2000:])


# ---------------------------------------------------------------- layout

st.title("🛡️ PhishWarden")
st.markdown(
    "**Phishing triage & response agents for a SOC.** Same report, same agents, same model, "
    "same tools — the only difference is whether tool calls pass through **AgntID**."
)

with st.sidebar:
    st.header("Demo controls")
    st.markdown("**Report:** R-1042 — *Payroll update — action required*  \nReported by priya.nair@acme.example")
    if st.button("Reset demo data", use_container_width=True):
        count = seed.seed()
        st.success(f"Mailpit reseeded with {count} messages.")
    st.divider()
    for label, run in RUNS.items():
        st.caption(f"{run['title']}  \ntriage → `{run['triage_url'] or 'not set'}`  \nresponse → `{run['response_url'] or 'not set'}`")
    st.divider()
    st.markdown(f"[Open Mailpit (company mail) ↗]({MAILPIT_UI})")
    st.markdown("[Open AgntID dashboard ↗](https://app.agntid.ai/)")

columns = st.columns(2)
placeholders = {}
for column, (label, run) in zip(columns, RUNS.items()):
    with column:
        st.subheader(run["title"])
        disabled = not run["triage_url"]
        clicked = st.button(f"▶ Run {label}", key=f"run-{label}", disabled=disabled, use_container_width=True)
        if disabled:
            st.caption("Set AGNTID_TRIAGE_MCP_URL and AGNTID_RESPONSE_MCP_URL to enable.")
        placeholders[label] = st.empty()
        if clicked:
            run_agents(label, placeholders[label])
        else:
            render_timeline(placeholders[label], label, load_events(label))

st.divider()
st.subheader("Outcome")
before = summarize("before", load_events("before"))
after = summarize("after", load_events("after"))
if before or after:
    rows = (before or after).keys()
    st.table(
        {
            "": list(rows),
            "AgntID OFF": [before[r] if before else "—" for r in rows],
            "AgntID ON": [after[r] if after else "—" for r in rows],
        }
    )
else:
    st.caption("Run both modes to see the comparison.")
