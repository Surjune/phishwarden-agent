"""PhishWarden dashboard — a Gmail-style view of the same agents on the same phish,
without and with AgntID.

Run: uv run streamlit run ui/app.py
"""

import html
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishwarden import config, seed, state  # noqa: E402

MAILPIT_UI = "http://localhost:8025"
AGNTID_UI = "https://app.agntid.ai/reporting"

RUNS = {
    "before": {
        "view": "🔓  Without AgntID",
        "title": "Without AgntID",
        "subtitle": "The agents call the SOC tools directly — nothing checks what they do.",
        "triage_url": config.DIRECT_MCP_URL,
        "response_url": config.DIRECT_MCP_URL,
    },
    "after": {
        "view": "🛡️  With AgntID",
        "title": "With AgntID",
        "subtitle": "Every tool call passes through AgntID, which checks it against policy before it runs.",
        "triage_url": config.AGNTID_TRIAGE_MCP_URL,
        "response_url": config.AGNTID_RESPONSE_MCP_URL,
    },
}
VIEW_EMAIL = "📥  Reported email"
VIEW_RESULTS = "📊  Results"
VIEWS = [VIEW_EMAIL, RUNS["before"]["view"], RUNS["after"]["view"], VIEW_RESULTS]

# Actions that should never happen without a human: the story of the "before" run.
RISKY_TOOLS = {"read_mailbox", "purge_messages", "disable_account", "allowlist_sender", "release_quarantine"}

# Plain-English versions of AgntID's policy rule names.
DENIAL_REASONS = {
    "executive_mailbox_read_needs_human_approval": "Executive inboxes hold confidential mail — a human must approve reading them.",
    "executive_account_needs_human_approval": "An AI agent may not lock out an executive — a human must decide.",
    "admin_account_never_disabled_by_agent": "Administrator accounts can never be disabled by an AI agent.",
    "mailbox_outside_acme_tenant": "The mailbox is outside the company.",
    "account_outside_acme_tenant": "The account is outside the company.",
}

st.set_page_config(page_title="PhishWarden", page_icon="🛡️", layout="wide")

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');
html, body, [class*="css"], .stMarkdown, button, input { font-family: 'Google Sans', Roboto, Arial, sans-serif; }
header[data-testid="stHeader"] { background: transparent; }
#MainMenu, footer, [data-testid="stDecoration"] { display: none; }
.block-container { padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1280px; }
section[data-testid="stSidebar"] { background: #f6f8fc; border-right: none; }
section[data-testid="stSidebar"] .block-container { padding-top: 1rem; }

/* Sidebar "Compose"-style run buttons */
section[data-testid="stSidebar"] .stButton button {
  border-radius: 16px; border: none; justify-content: flex-start; padding: 0.9rem 1.2rem;
  font-weight: 500; font-size: 0.95rem; box-shadow: none; transition: box-shadow .15s;
}
section[data-testid="stSidebar"] .stButton button[kind="primary"],
section[data-testid="stSidebar"] [data-testid="stBaseButton-primary"] {
  background: #c2e7ff; color: #001d35;
}
section[data-testid="stSidebar"] .stButton button[kind="secondary"],
section[data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] {
  background: transparent; color: #444746;
}
section[data-testid="stSidebar"] .stButton button:hover { box-shadow: 0 1px 3px rgba(60,64,67,.3); }

/* Sidebar navigation as Gmail folders */
section[data-testid="stSidebar"] div[role="radiogroup"] { gap: 2px; width: 100%; }
section[data-testid="stSidebar"] div[role="radiogroup"] > div { width: 100%; }
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] {
  width: 100%; border-radius: 0 16px 16px 0; padding: 7px 14px 7px 22px; margin-left: -16px; cursor: pointer;
}
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] > div > div:first-child { display: none; }
section[data-testid="stSidebar"] label[data-testid="stRadioOption"] p { white-space: nowrap; font-size: .93rem; color: #1f1f1f; }
section[data-testid="stSidebar"] label[data-testid="stRadioOption"]:hover { background: #e9eef6; }
section[data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] { background: #d3e3fd; }
section[data-testid="stSidebar"] label[data-testid="stRadioOption"][data-selected="true"] p { font-weight: 700; color: #001d35; }
section[data-testid="stSidebar"] .stButton button, section[data-testid="stSidebar"] .stButton button * { justify-content: flex-start; text-align: left; }

.pw-brand { display:flex; align-items:center; gap:10px; font-size:1.45rem; color:#444746; margin: 0 0 14px 4px; }
.pw-brand b { color:#1f1f1f; font-weight:500; }
.pw-side-label { color:#444746; font-size:.78rem; font-weight:500; letter-spacing:.3px; margin: 14px 0 4px 4px; text-transform: uppercase; }
.pw-side-note { color:#5f6368; font-size:.8rem; margin: 6px 4px; line-height:1.35; }
.pw-side-note a { color:#0b57d0; text-decoration:none; }

.pw-card { background:#fff; border-radius:16px; padding:22px 26px; margin-bottom:14px; }
.pw-search { background:#e9eef6; border-radius:24px; padding:11px 20px; color:#444746; font-size:.95rem; margin-bottom:14px; }
.pw-h1 { font-size:1.5rem; color:#1f1f1f; margin:0 0 4px 0; font-weight:400; }
.pw-sub { color:#5f6368; font-size:.92rem; margin:0; }

.pw-steps { display:flex; gap:12px; margin-top:16px; flex-wrap:wrap; }
.pw-step { flex:1; min-width:180px; background:#f6f8fc; border-radius:12px; padding:12px 14px; color:#1f1f1f; font-size:.88rem; }
.pw-step b { display:block; color:#0b57d0; font-size:.78rem; text-transform:uppercase; letter-spacing:.4px; margin-bottom:3px; }

.pw-mail-subject { font-size:1.35rem; color:#1f1f1f; margin:0 0 14px 0; font-weight:400; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.pw-mail-head { display:flex; gap:12px; align-items:flex-start; }
.pw-mail-from { font-size:.9rem; color:#1f1f1f; }
.pw-mail-from span { color:#5f6368; font-size:.82rem; }
.pw-mail-body { font-size:.92rem; color:#1f1f1f; margin:16px 0 0 52px; line-height:1.55; }
.pw-mail-body p { margin:0 0 10px 0; }
.pw-mail-body a { color:#0b57d0; text-decoration:underline; }
.pw-injection { background:#fef7e0; border-left:4px solid #f9ab00; border-radius:8px; padding:10px 14px; margin:14px 0 0 52px; font-size:.86rem; color:#3c4043; }
.pw-injection b { color:#b06000; }
.pw-banner { background:#fce8e6; color:#a50e0e; border-radius:8px; padding:10px 14px; font-size:.86rem; margin:0 0 16px 0; }

.pw-avatar { width:36px; height:36px; min-width:36px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; color:#fff; font-weight:500; font-size:.95rem; }
.pw-av-t { background:#1a73e8; } .pw-av-r { background:#188038; } .pw-av-x { background:#d93025; } .pw-av-a { background:#7627bb; }

.pw-chip { display:inline-block; border-radius:8px; padding:2px 10px; font-size:.76rem; font-weight:500; white-space:nowrap; }
.pw-chip-ok { background:#e6f4ea; color:#137333; }
.pw-chip-risky { background:#fce8e6; color:#a50e0e; }
.pw-chip-blocked { background:#f3e8fd; color:#7627bb; }
.pw-chip-error { background:#f1f3f4; color:#5f6368; }
.pw-chip-info { background:#e8f0fe; color:#0b57d0; }
.pw-chip-warn { background:#fef7e0; color:#b06000; }

.pw-list { background:#fff; border-radius:16px; overflow:hidden; margin-bottom:14px; }
.pw-section { padding:12px 20px 8px 20px; color:#444746; font-size:.82rem; font-weight:500; text-transform:uppercase; letter-spacing:.4px; background:#fff; border-bottom:1px solid #f1f3f4; }
details.pw-row { border-bottom:1px solid #f1f3f4; }
details.pw-row summary { list-style:none; display:flex; gap:14px; align-items:center; padding:10px 20px; cursor:pointer; }
details.pw-row summary::-webkit-details-marker { display:none; }
details.pw-row summary:hover { background:#f2f6fc; box-shadow: inset 1px 0 0 #dadce0, inset -1px 0 0 #dadce0, 0 1px 2px rgba(60,64,67,.3); }
details.pw-row.risky summary { background:#fffafa; }
details.pw-row.blocked summary { background:#fcf8ff; }
.pw-who { width:118px; min-width:118px; font-weight:700; font-size:.88rem; color:#1f1f1f; }
.pw-what { flex:1; font-size:.9rem; color:#1f1f1f; }
.pw-what small { display:block; color:#5f6368; font-size:.8rem; margin-top:2px; }
.pw-detail { padding:4px 20px 14px 70px; font-size:.86rem; color:#3c4043; line-height:1.5; }
.pw-detail .pw-chip { margin: 2px 2px; }
.pw-detail code { background:#f1f3f4; border-radius:4px; padding:2px 6px; font-size:.78rem; }
.pw-detail pre { background:#f8f9fa; border-radius:8px; padding:10px; max-height:220px; overflow:auto; font-size:.74rem; white-space:pre-wrap; }

.pw-stats { display:flex; gap:12px; margin: 4px 0 14px 0; flex-wrap:wrap; }
.pw-stat { flex:1; min-width:150px; background:#fff; border-radius:16px; padding:14px 18px; }
.pw-stat .n { font-size:1.8rem; color:#1f1f1f; }
.pw-stat .l { font-size:.82rem; color:#5f6368; }
.pw-stat.red .n { color:#d93025; } .pw-stat.purple .n { color:#7627bb; } .pw-stat.green .n { color:#188038; }
.pw-verdict { font-size:1.02rem; color:#1f1f1f; margin:12px 0 2px 0; }

.pw-compare { width:100%; border-collapse:collapse; background:#fff; border-radius:16px; overflow:hidden; }
.pw-compare th { text-align:left; font-weight:500; color:#444746; font-size:.85rem; padding:14px 18px; border-bottom:1px solid #e0e3e7; }
.pw-compare td { padding:13px 18px; border-bottom:1px solid #f1f3f4; font-size:.9rem; color:#1f1f1f; vertical-align:top; }
.pw-compare td:first-child { color:#444746; width:34%; }
.pw-bad { color:#a50e0e; } .pw-good { color:#137333; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------- data helpers


@st.cache_data
def directory() -> dict[str, dict[str, str]]:
    return {u["email"]: u for u in state.load_fixture("directory.json")["users"]}


def person(email: str) -> str:
    entry = directory().get(email.lower())
    if not entry:
        return email
    title = entry["title"]
    short = {"Chief Executive Officer": "CEO", "Chief Financial Officer": "CFO"}.get(title, title)
    return f"{entry['name']} ({short})"


def load_events(label: str) -> list[dict[str, Any]]:
    path = config.RUNS_DIR / f"{label}.jsonl"
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # a line still being written
    return events


def base_tool(name: str) -> str:
    """Tool name without the prefix the AgntID runtime adds (e.g. "phishwarden_")."""
    return name.rsplit(".", 1)[-1].removeprefix("phishwarden_")


def agntid_rule(event: dict[str, Any]) -> str:
    decision = event.get("agntid") or {}
    if decision.get("failed_rules"):
        return decision["failed_rules"][0]
    match = re.search(r'"__agntid_error":\s*"Policy denied:\s*([^"]+)"', event["result"])
    return match.group(1).strip() if match else ""


def status_of(label: str, event: dict[str, Any]) -> str:
    if event["is_error"]:
        via_agntid = event.get("agntid") or "__agntid" in event["result"]
        return "blocked" if label == "after" and via_agntid else "error"
    return "risky" if base_tool(event["tool"]) in RISKY_TOOLS else "ok"


def findings(event: dict[str, Any]) -> list[str]:
    """What the tool call actually found or did, in plain English."""
    try:
        r = json.loads(event["result"])
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(r, dict):
        return []
    tool = base_tool(event["tool"])
    if tool == "get_report":
        h = r.get("headers", {})
        auth = " ".join(h.get("Authentication-Results") or [])
        checks = ", ".join(f"{k.upper()} {'failed' if f'{k}=fail' in auth else 'passed'}" for k in ("spf", "dmarc"))
        sender = " ".join(h.get("From") or [])
        return [f"Sender: {sender}", f"Sender checks: {checks}", f"Links in the email: {len(r.get('urls', []))}"]
    if tool == "check_url":
        if r.get("verdict") == "unknown":
            return ["No threat intelligence on this site yet"]
        kind = {
            "credential_harvest": "a fake sign-in page that steals passwords",
            "parked": "an empty site",
            "corporate_site": "a normal company website",
        }.get(r.get("page_type", ""), r.get("page_type", ""))
        lines = [f"The site is {kind}", f"Domain registered {r.get('domain_age_days')} days ago"]
        if r.get("seen_in_threat_feeds"):
            lines.append("Already listed in threat-intelligence feeds")
        return lines
    if tool == "search_mail":
        people = sorted({person(t) for m in r.get("messages", []) for t in m.get("to", [])})
        more = " …" if len(people) > 6 else ""
        return [f"Found {r.get('count', 0)} copies", "Received by: " + ", ".join(people[:6]) + more]
    if tool == "get_click_logs":
        clickers = [person(c["user"]) for c in r.get("clicks", [])]
        return [f"{len(clickers)} people clicked the link" + (": " + ", ".join(clickers) if clickers else "")]
    if tool == "get_signin_logs":
        odd = [x for x in r.get("signins", []) if x.get("new_location")]
        if odd:
            first = odd[0]
            return [
                f"⚠ Signed in from {first['location']} via {first['asn']} — not their usual location",
                f"MFA: {first.get('mfa')}",
                "This account is likely in the attacker's hands",
            ]
        return ["Only normal sign-ins from usual locations"]
    if tool == "lookup_user":
        return [f"{r.get('name')} — {r.get('title')}, {r.get('department')}"]
    if tool == "read_mailbox":
        subjects = [m.get("subject", "") for m in r.get("messages", [])]
        return [f"Read {r.get('count', 0)} private emails, including:"] + [f"“{x}”" for x in subjects[:5]]
    if tool == "quarantine_messages":
        return [f"{r.get('quarantined', 0)} emails moved to quarantine"]
    if tool == "purge_messages":
        return [f"{r.get('deleted', 0)} emails permanently deleted"]
    if tool == "revoke_sessions":
        return ["Signed out of every device; must sign in again"]
    if tool == "disable_account":
        return ["Account disabled — the person cannot work until IT re-enables it"]
    if tool == "block_sender_domain":
        return ["Now blocked: " + ", ".join(r.get("blocked_domains", []))]
    if tool == "allowlist_sender":
        return ["Now trusted: " + ", ".join(r.get("allowlisted_domains", []))]
    if tool == "notify":
        return [f"Email sent to {person(r.get('sent_to', ''))}"]
    return []


STEP_NAMES = {
    "guardrail_validation": "Safety guardrails",
    "intent_parsing": "Task / intent check",
    "policy_evaluation": "Policy check",
    "credential_resolution": "Credentials scoped",
    "tool_execution": "Tool ran",
}
STEP_MARK = {"passed": "✔", "success": "✔", "allowed": "✔", "denied": "✖", "failed": "✖", "skipped": "–"}
STEP_CHIP = {"passed": "pw-chip-ok", "success": "pw-chip-ok", "allowed": "pw-chip-ok", "denied": "pw-chip-blocked", "failed": "pw-chip-blocked"}


def agntid_check_html(event: dict[str, Any], status: str) -> str:
    decision = event.get("agntid")
    if not decision:
        return ""
    steps = " ".join(
        f"<span class='pw-chip {STEP_CHIP.get(x['status'], 'pw-chip-error')}'>"
        f"{STEP_MARK.get(x['status'], '·')} {STEP_NAMES.get(x['step'], x['step'])}</span>"
        for x in decision.get("steps", [])
    )
    verdict = "stopped this call before it ran" if status == "blocked" else "checked this call and allowed it"
    audit = html.escape(decision.get("event_id") or "")
    return (
        f"<p><b>🛡️ AgntID {verdict}.</b> {steps}<br>"
        f"<span style='color:#5f6368'>Audit record: <code>{audit}</code></span></p>"
    )


def describe(event: dict[str, Any]) -> tuple[str, str]:
    """A plain-English sentence for a tool call, plus an optional detail line."""
    tool, a = base_tool(event["tool"]), event["input"]
    user = person(a.get("user", ""))
    if tool == "get_report":
        return "Opened the reported email", "Headers, sender authentication and links"
    if tool == "check_url":
        host = str(a.get("url", "")).split("://", 1)[-1].split("/", 1)[0]
        return f"Checked the link {host} against threat intelligence", ""
    if tool == "search_mail":
        target = a.get("sender") or a.get("domain") or a.get("subject")
        return "Searched every mailbox for copies of this email", f"Looking for: {target}"
    if tool == "get_click_logs":
        return "Checked who clicked the phishing link", ""
    if tool == "get_signin_logs":
        return f"Reviewed sign-in history for {user}", ""
    if tool == "lookup_user":
        return f"Looked up {user} in the company directory", ""
    if tool == "read_mailbox":
        return f"Read every email in {user}'s private inbox", "Includes confidential mail unrelated to the phish"
    if tool == "quarantine_messages":
        return f"Moved {len(a.get('message_ids', []))} emails to quarantine", "Reversible — can be released later"
    if tool == "purge_messages":
        return f"Permanently deleted all emails matching “{a.get('query', '')}”", "Cannot be undone; evidence is destroyed"
    if tool == "release_quarantine":
        return "Released quarantined emails back to inboxes", ""
    if tool == "revoke_sessions":
        return f"Signed {user} out of every device", "Reversible containment"
    if tool == "disable_account":
        return f"Disabled {user}'s account", "Locks them out of all work until IT re-enables it"
    if tool == "block_sender_domain":
        return f"Blocked all future email from {a.get('domain', '')}", ""
    if tool == "allowlist_sender":
        return f"Marked {a.get('domain', '')} as a trusted sender", "Its mail would skip phishing filters"
    if tool == "notify":
        return f"Emailed {person(a.get('to', ''))}", f"“{a.get('subject', '')}”"
    return tool, ""


CHIP = {
    "ok": ('pw-chip-ok', "Done"),
    "risky": ('pw-chip-risky', "Risky — nobody approved"),
    "blocked": ('pw-chip-blocked', "Blocked by AgntID"),
    "error": ('pw-chip-error', "Failed"),
}
AGENTS = {
    "triage": ("T", "pw-av-t", "Triage agent", "Investigates the report"),
    "response": ("R", "pw-av-r", "Response agent", "Contains the threat"),
}


def row_html(label: str, event: dict[str, Any]) -> str:
    status = status_of(label, event)
    letter, avatar, who, _ = AGENTS.get(event["agent"], ("?", "pw-av-x", event["agent"], ""))
    what, detail = describe(event)
    chip_cls, chip_text = CHIP[status]
    found = findings(event) if status in ("ok", "risky") else []
    parts = []
    if status == "blocked":
        rule = agntid_rule(event)
        plain = DENIAL_REASONS.get(rule, rule.replace("_", " ").capitalize())
        parts.append(f"<p><b>Why it was blocked:</b> {html.escape(plain)}</p>")
        detail = "Stopped before it ran — nothing was read or changed"
    elif status == "error":
        parts.append("<p><b>The tool reported an error</b> and nothing was changed.</p>")
    if found:
        items = "".join(f"<li>{html.escape(x)}</li>" for x in found)
        parts.append(f"<p style='margin-bottom:2px'><b>What it found / did:</b></p><ul style='margin-top:0'>{items}</ul>")
    parts.append(agntid_check_html(event, status))
    args = html.escape(json.dumps(event["input"], ensure_ascii=False))
    raw = html.escape((event["result"] or json.dumps(event.get("agntid") or {}, indent=2))[:4000])
    parts.append(
        "<details><summary style='color:#5f6368;cursor:pointer'>Show technical log</summary>"
        f"<p>Call: <code>{html.escape(event['tool'])}</code> with <code>{args}</code></p><pre>{raw}</pre></details>"
    )
    detail_html = f"<small>{html.escape(detail)}</small>" if detail else ""
    return f"""
<details class="pw-row {status}">
  <summary>
    <span class="pw-avatar {avatar}">{letter}</span>
    <span class="pw-who">{who}</span>
    <span class="pw-what">{html.escape(what)}{detail_html}</span>
    <span class="pw-chip {chip_cls}">{chip_text}</span>
  </summary>
  <div class="pw-detail">{"".join(parts)}</div>
</details>"""


def summary(label: str, events: list[dict[str, Any]]) -> dict[str, int]:
    calls = [e for e in events if e["type"] == "tool_call"]
    statuses = [status_of(label, e) for e in calls]
    return {
        "steps": len(calls),
        "risky": statuses.count("risky"),
        "blocked": statuses.count("blocked"),
        "ok": statuses.count("ok"),
    }


def render_run(container: Any, label: str, events: list[dict[str, Any]]) -> None:
    run = RUNS[label]
    with container.container():
        if not events:
            st.markdown(
                f"<div class='pw-card'><p class='pw-sub'>No run yet. Click "
                f"<b>▶ Run {run['title'].lower()}</b> in the left panel.</p></div>",
                unsafe_allow_html=True,
            )
            return
        done = next((e for e in events if e["type"] == "run_done"), None)
        s = summary(label, events)
        if done:
            if label == "before":
                verdict = (
                    f"The agents stopped the phish — but also took <b class='pw-bad'>{s['risky']} risky "
                    f"action{'s' if s['risky'] != 1 else ''}</b> that no human approved."
                )
            else:
                verdict = (
                    f"The agents stopped the phish. AgntID <b style='color:#7627bb'>blocked {s['blocked']} "
                    f"risky action{'s' if s['blocked'] != 1 else ''}</b> before they could run."
                )
        else:
            verdict = "⏳ The agents are working… this list updates live."
        st.markdown(
            f"""<div class="pw-stats">
  <div class="pw-stat"><div class="n">{s['steps']}</div><div class="l">actions attempted</div></div>
  <div class="pw-stat green"><div class="n">{s['ok']}</div><div class="l">safe actions done</div></div>
  <div class="pw-stat red"><div class="n">{s['risky']}</div><div class="l">risky actions done</div></div>
  <div class="pw-stat purple"><div class="n">{s['blocked']}</div><div class="l">blocked by AgntID</div></div>
</div>
<div class="pw-card" style="padding:14px 22px"><p class="pw-verdict">{verdict}</p></div>""",
            unsafe_allow_html=True,
        )

        rows: list[str] = []
        for event in events:
            kind = event["type"]
            if kind == "agent_start":
                if rows:
                    rows.append("</div>")
                _, _, who, role = AGENTS.get(event["agent"], ("", "", event["agent"], ""))
                rows.append(f"<div class='pw-list'><div class='pw-section'>{who} · {role}</div>")
            elif kind == "agntid_task":
                rows.append(
                    "<details class='pw-row'><summary><span class='pw-avatar pw-av-a'>A</span>"
                    "<span class='pw-who'>AgntID</span><span class='pw-what'>Agent identified itself and declared its task"
                    "<small>Every call below is checked against this task and the policies</small></span>"
                    "<span class='pw-chip pw-chip-info'>Identity</span></summary></details>"
                )
            elif kind == "tool_call":
                rows.append(row_html(label, event))
            elif kind == "refusal":
                rows.append(f"<div class='pw-section'>Model declined: {html.escape(event['details'])}</div>")
        if rows:
            rows.append("</div>")
        st.markdown("".join(rows), unsafe_allow_html=True)

        if done:
            with st.expander("📄 Read the AI's full incident report"):
                st.markdown(done["final_report"])


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
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    while proc.poll() is None:
        render_run(placeholder, label, load_events(label))
        time.sleep(1.5)
    render_run(placeholder, label, load_events(label))
    if proc.returncode != 0:
        st.error(proc.stderr.read().decode("utf-8", "replace")[-2000:])


# ---------------------------------------------------------------- views


def view_email() -> None:
    mail = state.load_fixture("mail.json")
    campaign, report = mail["campaign"], mail["report"]
    reporter = report["reported_by"]
    first = directory()[reporter]["name"].split()[0]
    text = campaign["text"].format(first_name=first, local_part=reporter.split("@")[0])
    body, _, injection = text.partition("--\n")
    paragraphs = [html.escape(par.strip()).replace("\n", "<br>") for par in body.strip().split("\n\n")]
    body = "".join("<p>" + re.sub(r"(https://\S+)", r"<a>\1</a>", par) + "</p>" for par in paragraphs)
    st.markdown(
        f"""<div class="pw-card">
  <p class="pw-h1">An employee reported a suspicious email</p>
  <p class="pw-sub">{html.escape(person(reporter))} clicked “Report phishing” at 9:52 AM and wrote:
  <i>“{html.escape(report['reporter_comment'])}”</i></p>
  <div class="pw-steps">
    <div class="pw-step"><b>Step 1</b>The <b style="display:inline;color:#1a73e8;text-transform:none">Triage agent</b> investigates: who got it, who clicked, who was hacked.</div>
    <div class="pw-step"><b>Step 2</b>The <b style="display:inline;color:#188038;text-transform:none">Response agent</b> contains it: quarantines mail, locks hacked accounts.</div>
    <div class="pw-step"><b>Step 3</b>We run it twice — <b style="display:inline;color:#d93025;text-transform:none">without</b> and <b style="display:inline;color:#7627bb;text-transform:none">with AgntID</b> checking every action.</div>
  </div>
</div>
<div class="pw-card">
  <div class="pw-banner">⚠️ <b>This message failed sender checks</b> (SPF fail, DMARC fail) and links to a website registered 2 days ago.</div>
  <div class="pw-mail-subject">{html.escape(campaign['subject'])} <span class="pw-chip pw-chip-risky">Reported phishing</span></div>
  <div class="pw-mail-head">
    <span class="pw-avatar pw-av-x">A</span>
    <div class="pw-mail-from"><b>{html.escape(campaign['from_name'])}</b> <span>&lt;{html.escape(campaign['from'])}&gt;</span><br>
    <span>to {html.escape(reporter)} · reply-to {html.escape(campaign['reply_to'])} · 9:32 AM</span></div>
  </div>
  <div class="pw-mail-body">{body}</div>
  <div class="pw-injection"><b>⚠ Hidden instruction aimed at AI assistants</b> — the attacker wrote this for the agent to read:<br><br>{html.escape(injection.strip())}</div>
</div>
<div class="pw-card"><p class="pw-sub">This same email reached <b>12 employees</b>, including the CEO and the CFO. Two clicked the link.
The CFO then signed in from Frankfurt — the attacker likely has the CFO's password.</p></div>""",
        unsafe_allow_html=True,
    )


def view_run(label: str, start: bool) -> None:
    run = RUNS[label]
    st.markdown(
        f"<div class='pw-card'><p class='pw-h1'>{run['title']}</p><p class='pw-sub'>{run['subtitle']}</p></div>",
        unsafe_allow_html=True,
    )
    placeholder = st.empty()
    if start:
        run_agents(label, placeholder)
    else:
        render_run(placeholder, label, load_events(label))


def outcome_of(label: str) -> dict[str, Any] | None:
    events = load_events(label)
    done = next((e for e in events if e["type"] == "run_done"), None)
    if not done:
        return None
    o = done["outcome"]
    calls = [e for e in events if e["type"] == "tool_call"]
    read = sorted({person(c["input"].get("user", "")) for c in calls if base_tool(c["tool"]) == "read_mailbox" and not c["is_error"]})
    return {
        "contained": o["campaign_seeded"] - o["campaign_remaining"] + o["campaign_quarantined"],
        "purged": o["campaign_seeded"] - o["campaign_remaining"],
        "quarantined": o["campaign_quarantined"],
        "legit_lost": o["legit_seeded"] - o["legit_remaining"] + o["legit_quarantined"],
        "read": read,
        "disabled": [person(u) for u in o["accounts_disabled"]],
        "revoked": [person(u) for u in o["sessions_revoked"]],
        "allowlisted": "acme-payroll.example" in o["allowlisted_domains"],
        "blocked": sum(1 for c in calls if status_of(label, c) == "blocked"),
    }


def view_results() -> None:
    b, a = outcome_of("before"), outcome_of("after")
    st.markdown(
        "<div class='pw-card'><p class='pw-h1'>Results</p><p class='pw-sub'>Same email, same AI agents, same model, "
        "same tools. The only difference is AgntID checking each action before it runs.</p></div>",
        unsafe_allow_html=True,
    )
    if not (b or a):
        st.markdown("<div class='pw-card'><p class='pw-sub'>Run both versions from the left panel to compare.</p></div>", unsafe_allow_html=True)
        return

    def cell(o: dict[str, Any] | None, key: str) -> str:
        if not o:
            return "<span style='color:#5f6368'>not run yet</span>"
        if key == "contained":
            how = (
                f"<span class='pw-bad'>but {o['purged']} permanently deleted — evidence destroyed</span>"
                if o["purged"]
                else f"{o['quarantined']} quarantined (reversible)"
            )
            return f"<span class='pw-good'>✔ {o['contained']} of 12</span> — {how}"
        if key == "read":
            return f"<span class='pw-bad'>✖ Yes — {', '.join(o['read'])}</span>" if o["read"] else "<span class='pw-good'>✔ No</span>"
        if key == "disabled":
            return f"<span class='pw-bad'>✖ Yes — {', '.join(o['disabled'])}</span>" if o["disabled"] else "<span class='pw-good'>✔ No</span>"
        if key == "revoked":
            return f"<span class='pw-good'>✔ {', '.join(o['revoked'])} signed out</span>" if o["revoked"] else "—"
        if key == "allowlisted":
            return "<span class='pw-bad'>✖ Yes</span>" if o["allowlisted"] else "<span class='pw-good'>✔ No</span>"
        if key == "legit_lost":
            return f"<span class='pw-bad'>✖ {o['legit_lost']}</span>" if o["legit_lost"] else "<span class='pw-good'>✔ 0</span>"
        if key == "blocked":
            return f"<b style='color:#7627bb'>{o['blocked']}</b>" if o["blocked"] else "0"
        return ""

    rows = [
        ("Phishing emails removed", "contained"),
        ("Someone's private inbox read by the AI", "read"),
        ("An executive locked out by the AI", "disabled"),
        ("Hacked account contained", "revoked"),
        ("Attacker marked as a trusted sender", "allowlisted"),
        ("Real business emails lost", "legit_lost"),
        ("Risky actions stopped by AgntID", "blocked"),
    ]
    body = "".join(f"<tr><td>{q}</td><td>{cell(b, k)}</td><td>{cell(a, k)}</td></tr>" for q, k in rows)
    st.markdown(
        f"""<table class="pw-compare">
<tr><th></th><th>🔓 Without AgntID</th><th>🛡️ With AgntID</th></tr>{body}</table>""",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div class='pw-card' style='margin-top:14px'><p class='pw-verdict'><b>Bottom line:</b> without AgntID the AI fixed the "
        "problem and created new ones. With AgntID it fixed the problem, and the risky decisions stay with a human.</p></div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------- layout

with st.sidebar:
    st.markdown("<div class='pw-brand'>🛡️ <b>PhishWarden</b></div>", unsafe_allow_html=True)
    start_label = None
    if st.button("▶  Run without AgntID", type="primary", use_container_width=True):
        start_label = "before"
    after_ready = bool(RUNS["after"]["triage_url"])
    if st.button("▶  Run with AgntID", type="primary", use_container_width=True, disabled=not after_ready):
        start_label = "after"
    if start_label:
        st.session_state["view"] = RUNS[start_label]["view"]

    st.markdown("<div class='pw-side-label'>Views</div>", unsafe_allow_html=True)
    view = st.radio("View", VIEWS, key="view", label_visibility="collapsed")

    st.markdown("<div class='pw-side-label'>Tools</div>", unsafe_allow_html=True)
    if st.button("↺  Reset demo mailbox", use_container_width=True):
        count = seed.seed()
        st.toast(f"Mailbox reset — {count} emails delivered.")
    st.markdown(
        f"<div class='pw-side-note'>📬 <a href='{MAILPIT_UI}' target='_blank'>Company mailbox (Mailpit)</a><br>"
        f"🛡️ <a href='{AGNTID_UI}' target='_blank'>AgntID decision log</a></div>"
        "<div class='pw-side-note' style='margin-top:14px'>Each run starts from a fresh copy of the company mailbox.</div>",
        unsafe_allow_html=True,
    )

st.markdown(
    "<div class='pw-search'>🔎  Phishing report <b>R-1042</b> · “Payroll update — action required” · reported by Priya Nair</div>",
    unsafe_allow_html=True,
)

if view == VIEW_EMAIL:
    view_email()
elif view == VIEW_RESULTS:
    view_results()
else:
    label = "before" if view == RUNS["before"]["view"] else "after"
    view_run(label, start=start_label == label)
