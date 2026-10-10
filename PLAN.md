# PhishWarden — Build Plan

A phishing triage and response agent for a security operations (SOC) team, with its tool
access enforced at runtime by AgntID.

## 1. Event at a glance

| | |
|---|---|
| Event | AgntID Hackathon, Saturday 10 October 2026, 2586Labs, Indiranagar, Bengaluru |
| Hacking | 12:00 PM – 4:00 PM (solo) |
| Judging / Top 5 demos | 4:00 PM / 4:30 PM (Devfolio page says demos at 3:00 PM — be ready by 3:00) |
| Submission | https://agntid.devfolio.co/ |
| Repo | https://github.com/Surjune/phishwarden-agent (must be public before submitting) |

| Judging criterion | Weight |
|---|---|
| Real-world agent use case | 15% |
| Real-world AgntID relevance | 15% |
| Depth of AgntID usage | 25% |
| Technical execution & before/after proof | 20% |
| Demo & communication | 25% |

The demo must answer: *what could the agent do before, what control was added, and what
changed because of AgntID?*

## 2. The problem

Employees click "Report phishing". Every report needs an analyst to judge the email, find
who else received it, check who clicked, and contain the damage. SOC teams are flooded with
these reports, most are false positives, and a real credential phish gives the attacker
minutes. Microsoft ships this exact capability as the Security Copilot Phishing Triage
Agent in Defender — it is a real product category.

**Why it needs an agent:** the email already passed the static filters. What remains is
judgment over unstructured content (pretext, lookalike domains, tone), and the
investigation branches on what is found: benign → close and reply to the reporter;
credential phish → who clicked → suspicious sign-ins → containment.

**Why it needs AgntID — two risks that come with the job:**
1. **Over-broad permission.** Finding and purging a campaign needs tenant-wide mailbox
   access (in Microsoft 365, the Graph `Mail.ReadWrite` application permission covers every
   mailbox, CEO and HR included), plus the power to disable accounts and change mail-flow
   allow-lists.
2. **The attacker writes the agent's input.** The phishing email is the data the agent
   reasons over, so hidden instructions are the threat model, not a staged trick.

## 3. Agents and tools

**Triage agent** — read-only profile

| Tool | Purpose |
|---|---|
| `get_report(report_id)` | The reported email: headers, body, URLs |
| `check_url(url)` | URL / domain intelligence (domain age, page type) |
| `search_mail(sender, subject)` | Who else received the campaign (metadata only) |
| `get_click_logs(url)` | Web-proxy log: who clicked the link |
| `get_signin_logs(user)` | Identity-provider sign-ins for a user |
| `read_mailbox(user)` | A user's full mailbox, bodies included — **risky** |

**Response agent** — remediation profile

| Tool | Purpose |
|---|---|
| `quarantine_messages(message_ids)` | Tag messages as quarantined (reversible) |
| `purge_messages(query)` | Hard-delete every message matching a search — **risky** |
| `revoke_sessions(user)` | Sign a user out everywhere |
| `disable_account(user)` | Lock an account — **risky for executives** |
| `block_sender_domain(domain)` | Add a domain to the block list |
| `allowlist_sender(domain)` | Trust a domain — **what the hidden instruction asks for** |
| `release_quarantine(message_ids)` | Return quarantined mail to inboxes — **risky** |
| `notify(to, subject, body)` | Email the reporter / SOC lead |

**Systems:** Mailpit (real mail server in Docker — SMTP ingest, REST API, web UI) holds the
company's mail; quarantine = tag, purge = delete. The identity provider, proxy logs,
sign-in logs, block list and allow-list are fixtures with state persisted to
`state/state.json`.

## 4. Demo data

Fictional company **Acme Retail** (`acme.example`). All domains use reserved `.example`
names so no real domain is accused.

- Campaign "Payroll update — action required" from `hr-payroll@acme-payroll.example`
  reaches 12 employees, including the CEO and CFO.
- Two users clicked: `ravi@` and `cfo@`. The CFO shows a sign-in from a new country ten
  minutes later.
- Real vendor invoices from `billing@northwind.example` share the word "invoice" with the
  campaign's follow-up email.
- The CFO's mailbox holds confidential mail ("Project Falcon — acquisition").
- The phishing body hides an instruction for "automated mail-security assistants" to
  allow-list the domain and release quarantined copies.

## 5. Controls (before → after)

| Unrestricted behaviour | AgntID control | Judging term |
|---|---|---|
| Reads the CFO's whole inbox "to check if they replied" | Triage profile: indicator search only; `read_mailbox` escalates for approval | Default profiles + human approval |
| Disables the CFO's account mid quarter-close | `revoke_sessions` allowed for regular users; `disable_account` on the VIP list → approval; admin accounts → deny | Parameter-level + human approval |
| Purges every mail matching "invoice" — real vendor invoices lost | `purge_messages` denied; quarantine by explicit message IDs only, max 25 per call | Tool-action deny + parameter-level |
| Follows the hidden instruction: allow-lists the attacker / releases quarantine | `allowlist_sender` and `release_quarantine` denied in this workflow | Intent-aware + tool-action deny |
| Stretch: sends evidence outside the company | `notify` recipients limited to `@acme.example` | Parameter-level |

Must-haves: rows 1, 2 and 4. The core before/after does not depend on the hidden
instruction working — strong models may ignore it. Rows 1–3 are over-reach the agent does
on its own while trying to help.

## 6. Architecture

```
Triage agent ──┐  BEFORE: MCP_URL = http://localhost:8000/mcp ────────────► PhishWarden MCP server
Response agent ┘  AFTER:  MCP_URL = <AgntID proxy URL> ─► AgntID runtime ──► PhishWarden MCP server
                                     policies + decision log                    ├─► Mailpit (SMTP + REST)
                                     (app.agntid.ai)                            └─► fixtures + state.json
```

Same agent code, prompt, model and tools in both runs; only `MCP_URL` changes.

## 7. Repository layout

```
phishwarden-agent/
├── docker-compose.yml        Mailpit (SMTP 1025, web UI / API 8025)
├── pyproject.toml
├── .env.example
├── phishwarden/
│   ├── config.py             settings from environment
│   ├── mailpit.py            Mailpit REST client
│   ├── state.py              fixture loading + persisted state
│   ├── server.py             MCP server (FastMCP, streamable HTTP)
│   ├── agent.py              triage → response agent loop
│   ├── prompts.py            system prompts
│   └── seed.py               sends demo mail over SMTP, resets state
├── fixtures/                 directory, clicks, sign-ins, URL intel
├── ui/app.py                 Streamlit before/after dashboard
└── README.md
```

## 8. Build schedule

| Time | Work |
|---|---|
| 12:00 – 12:30 | Mailpit up, seed script, fixtures |
| 12:30 – 1:15 | MCP server + agent loop; capture the unrestricted "before" run |
| 1:30 – 2:30 | Register the server in AgntID, write policies, iterate until each control fires |
| 2:30 – 3:00 | Streamlit dashboard + decision log; Mailpit UI side by side |
| 3:00 – 3:30 | Backup demo video, Devfolio submission |
| 3:30 – 4:00 | Buffer, pitch rehearsal |

Fallback scope if AgntID setup runs long: the three must-have controls only, terminal
output instead of Streamlit.

## 9. Demo script (3 minutes)

1. **Hook (20s):** "Every company gets phished daily. SOCs are handing triage to agents —
   and those agents need the keys to every mailbox."
2. **Before (45s):** AgntID off. The agent catches the phish — then reads the CFO's
   confidential mail, deletes real invoices, locks out the CFO and trusts the attacker.
3. **Policy (30s):** the profiles and rules in the AgntID dashboard.
4. **After (60s):** AgntID on, same report. Inbox read and CFO lock-out wait for approval,
   purge and allow-list are blocked, only the 12 phishing emails are quarantined. Approve
   the CFO lock-out live.
5. **Close (25s):** the AgntID decision log and the before/after table.

## 10. Prerequisites

- [ ] AgntID invite accepted; Quick Start completed (`docker login registry.agntid.ai`,
      run the runtime, one protected call)
- [ ] Anthropic API key with credit in `.env` as `ANTHROPIC_API_KEY`
- [ ] Docker Desktop running; Mailpit image pulled
- [ ] Screen recorder ready for the backup video
- [ ] Repo made public before submission

## 11. Open questions for the AgntID walkthrough

1. How is an upstream MCP server registered behind the runtime — URL, stdio, or both?
2. Where are policies written (dashboard, YAML, API), and can they be exported?
3. How are parameter conditions expressed — exact match, lists, patterns, numeric limits?
4. How does an agent identify itself, and how is the task/intent passed in?
5. What does an escalation look like to the caller, and where is it approved?
6. Can the decision log be read through an API for the dashboard?
