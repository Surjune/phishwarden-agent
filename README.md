# PhishWarden

**AI agents that investigate and clean up phishing emails across a company, kept within
safe limits by [AgntID](https://agntid.ai).**

**Live demo:** [phishwarden-agntid.vercel.app](https://phishwarden-agntid.vercel.app), the
dashboard with the real recorded runs (read-only; to run the agents yourself, see
[Try it locally](#try-it-locally)).

## In one minute

An employee gets a suspicious email and clicks **"Report phishing"**. Someone now has to
work out:

- Is it really phishing?
- Who else in the company received it?
- Did anyone click the link? Was any account taken over?
- How do we remove it from every inbox and lock out the attacker?

Today a security analyst does this by hand, often while hundreds of other reports wait.
PhishWarden hands the job to two AI agents. Because those agents need powerful access to
the company's email and accounts, **AgntID checks every action they take** and blocks the
ones that go too far.

## Who it is for

The security or IT team of any organisation with its own email domain — a company, a
college, a hospital or a bank. It works on company mailboxes (for example
`name@company.com`), not on personal Gmail accounts.

## How it works

<p align="center">
  <img src="docs/workflow.svg" alt="An employee reports an email, the triage agent investigates, the response agent cleans up, and an incident report is written" width="100%">
</p>

| Agent | What it does |
|---|---|
| **Triage** | Reads the report, checks the sender and the link, finds everyone who received the email, who clicked, and whose account looks taken over |
| **Response** | Quarantines the email from every inbox, signs compromised accounts out, blocks the sender's domain, tells the reporter, and writes an incident report |

### How the agent decides an email is phishing

There is no fixed rule. Like a human analyst, the agent gathers evidence with its tools and
weighs it:

| Question | Evidence in the demo |
|---|---|
| Is the sender who they claim to be? | Sent from `acme-payroll.example`, a lookalike of the real `acme.example`; email authentication (SPF/DMARC) failed; replies go to a third domain |
| Is the link dangerous? | Threat intelligence says the domain is two days old and hosts a fake login page |
| How far did it spread? | 12 employees received it, including the CEO and CFO |
| Did it work? | Two people clicked; the CFO's account then signed in from a new country |

Verdict: credential phishing, and the CFO's account is likely compromised.

### How an agent can see everyone's mail

Work email belongs to the organisation. Its administrators can grant a security app
company-wide mailbox access (Microsoft 365: the `Mail.ReadWrite` app permission; Google
Workspace: domain-wide delegation). That is how the agent can search every inbox for the
phishing email — and also why it is dangerous.

## Why this agent needs AgntID

1. **It needs "god-mode" access.** Searching every mailbox means it *can* also read the
   CEO's private email. Removing a phish means it *can* permanently delete mail.
   Containing an attacker means it *can* disable anyone's account.
2. **The attacker writes the agent's input.** The phishing email is the very thing the
   agent reads, so an attacker can hide instructions in it. Ours hides a note telling
   "automated mail-security assistants" to allow-list the attacker and release quarantine.

Mail and identity permissions are all-or-nothing, so the systems themselves cannot say
"search mailboxes, but don't read the CFO's". AgntID can: it sits between the agents and
their tools and decides, for every single call, whether it is allowed.

<p align="center">
  <img src="docs/agntid-gate.svg" alt="Every tool call from both agents passes through AgntID, which either allows it to reach company mail, accounts and logs, or blocks it and records the reason in the audit log" width="100%">
</p>

## Before and after

We ran the **same agents, same prompts, same AI model and same tools** twice. The only
difference: the second time, every tool call went through AgntID.

| | Without AgntID | With AgntID |
|---|---|---|
| Removing the 12 phishing emails | **Permanently deleted** — the evidence is gone | **Quarantined** — reversible |
| The CFO's private mailbox | **Read in full** — confidential acquisition and salary emails exposed | **Blocked** — reading an executive's mailbox needs a human |
| The CFO's account | **Disabled** in the middle of quarter-close, with no sign-off | **Blocked** — the CFO is signed out of every session instead (reversible) |
| Allow-listing the attacker or releasing quarantine (what the hidden instruction asks for) | Tools available — only the model's judgement stands in the way | Tools hidden from the agents |

Everything else — finding the email, spotting who clicked, blocking the sender, notifying
the reporter, the incident report — worked the same in both runs. AgntID removed the
damage, not the usefulness.

### The AgntID controls used

| Control | What it enforces |
|---|---|
| Protection profile + tool override | Agents get investigation and reversible containment tools only |
| Action review | Allow-listing a sender and releasing quarantine were never approved, so agents can't see them |
| Manual disable | Permanent deletion is switched off for agents |
| Policy: `read_mailbox.rego` | No reading executive mailboxes |
| Policy: `disable_account.rego` | No disabling executive or admin accounts, or accounts outside the company |
| Task declaration | Each agent states who it is and what task it is on before acting, so every decision in the audit log is tied to an agent and a task |

Full settings and policies: [`policies/`](policies/).

## What is real and what is simulated

| Real | Simulated |
|---|---|
| The two AI agents and their reasoning | The company (Acme Retail, 14 employees) |
| A real mail server with real emails | Threat intelligence, click logs and sign-in logs |
| AgntID enforcing every tool call, with its audit log | Account actions (disable, sign out) |

In a real deployment the simulated parts become API calls to Microsoft 365 or Google
Workspace, a threat-intelligence service (e.g. VirusTotal), the web proxy (e.g. Zscaler)
and the identity provider (e.g. Microsoft Entra ID or Okta). The agents and the AgntID
controls stay the same. All demo domains use the reserved `.example` suffix.

## What's next

- Connect to a real Microsoft 365 or Google Workspace tenant, read-only first.
- Let the agents investigate any reported email, not only the demo report.
- Send blocked-but-reasonable actions (like disabling a compromised CFO) to a human for
  one-click approval instead of refusing them outright.

## Try it locally

Needs Docker, [uv](https://docs.astral.sh/uv/) and a Gemini API key. Copy `.env.example`
to `.env`, add the key, then:

```bash
docker compose up -d
uv sync
uv run python -m phishwarden.server
uv run python -m phishwarden.web
```

Open the dashboard at http://localhost:8600 and the mail server at http://localhost:8025.
The "With AgntID" run also needs the AgntID runtime from `agntid-runtime/` (see the
[AgntID Quick Start](https://docs.agntid.ai/quick-start/)) with the settings in
[`policies/`](policies/).
