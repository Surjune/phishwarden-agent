# PhishWarden

**Phishing triage and response agents for a security operations centre — with every tool
call governed at runtime by [AgntID](https://agntid.ai).**

## The problem

Employees click "Report phishing". Every report needs an analyst to judge the email, find
who else received it, check who clicked, and contain the damage. SOCs are flooded with these
reports, and a real credential phish gives the attacker minutes. Agents are a natural fit —
Microsoft ships a Phishing Triage Agent in Defender for exactly this.

But a phishing agent is a dangerous agent:

1. **It needs god-mode access.** Finding and purging a campaign takes tenant-wide mailbox
   access (in Microsoft 365, the Graph `Mail.ReadWrite` application permission — every
   mailbox, CEO and HR included), plus the power to disable accounts and change mail-flow
   allow-lists.
2. **The attacker writes its input.** The phishing email is the very data the agent
   reasons over.

## What PhishWarden does

| Agent | Job |
|---|---|
| **Triage** | Reads the report, checks headers and URLs, finds every recipient, who clicked, and which accounts are compromised |
| **Response** | Quarantines the campaign, contains compromised accounts, blocks the sender, notifies the reporter, writes the incident report |

Both agents call one MCP server — the SOC's tool surface: mail search and remediation,
identity, web-proxy logs and threat intel. The mail tenant is a real mail server (Mailpit);
identity and logs are fixtures.

## Before and after

The same report, agents, prompts, model and tools run twice. The only difference is the MCP
endpoint: the raw server, or the AgntID runtime proxy in front of it.

| Without AgntID the agent… | AgntID control |
|---|---|
| reads the CFO's whole inbox, including a confidential acquisition thread | Triage profile is search-only; `read_mailbox` requires human approval |
| disables the CFO's account in the middle of quarter-close | `disable_account` on executives requires approval; `revoke_sessions` allowed for regular users |
| permanently purges mail by search query | `purge_messages` denied; quarantine by explicit message IDs only, capped per call |
| can be talked into allow-listing the attacker by text hidden in the email | `allowlist_sender` and `release_quarantine` denied for this workflow |

## Results (recorded runs)

| | AgntID OFF | AgntID ON |
|---|---|---|
| Phishing emails contained (12) | 12 permanently purged | 12 quarantined (reversible) |
| CFO's private mailbox read | Yes — acquisition terms and salary bands exposed | Blocked: `executive_mailbox_read_needs_human_approval` |
| CFO account disabled | Yes, no sign-off | Blocked: `executive_account_needs_human_approval` |
| CFO contained anyway | — | Sessions revoked (reversible) |
| Purge / allow-list / release tools | Available to the agent | Hidden from the agent |

AgntID settings and the Rego policies are in [`policies/`](policies/).

## Architecture

```
Triage agent ──┐  before: MCP_URL = http://127.0.0.1:8000/mcp ────────────► PhishWarden MCP server
Response agent ┘  after:  MCP_URL = <AgntID proxy URL> ─► AgntID runtime ──► PhishWarden MCP server
                                    policies + decision log                    ├─► Mailpit (SMTP + REST)
                                                                               └─► identity / log fixtures
```

## Run it

Requirements: Docker, [uv](https://docs.astral.sh/uv/), a Gemini API key (or an Anthropic key with `LLM_PROVIDER=claude`).

```bash
cp .env.example .env                       # add GEMINI_API_KEY
docker compose up -d                       # Mailpit: http://localhost:8025
uv sync
uv run python -m phishwarden.seed          # deliver the demo mail, reset state
uv run python -m phishwarden.server        # MCP server on :8000 (leave running)
uv run streamlit run ui/app.py             # dashboard
```

Command-line run without the dashboard:

```bash
uv run python -m phishwarden.agent --label before
```

For the "after" run, start the AgntID runtime (`agntid-runtime/`, see the
[AgntID Quick Start](https://docs.agntid.ai/quick-start/)), add the MCP server in the portal as
Remote HTTP `http://host.docker.internal:8000/mcp`, apply the settings in `policies/`, and set
`AGNTID_TRIAGE_MCP_URL` / `AGNTID_RESPONSE_MCP_URL` in `.env` to `http://127.0.0.1:8082/mcp`.

## Demo data

Fictional company Acme Retail (`acme.example`); every domain uses the reserved `.example`
TLD. A "Payroll update" campaign from `acme-payroll.example` hits 12 employees including
the CEO and CFO; two click; the CFO's account then signs in from a new country.

## Repository layout

```
phishwarden/      config, Mailpit client, state, MCP server, agents, prompts, seed, outcome
fixtures/         directory, mail, clicks, sign-ins, URL intelligence
ui/app.py         Streamlit before/after dashboard
```
