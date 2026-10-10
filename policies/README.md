# AgntID configuration for PhishWarden

Applied in the AgntID portal to runtime `ba3961b1…`, MCP server `phishwarden`
(Remote HTTP, `http://host.docker.internal:8000/mcp`).

| Layer | Setting | Effect |
|---|---|---|
| Runtime protection profile | Medium (reviewed) | Default: read and lower-risk writes only |
| Tool-level override | PhishWarden → Low | Reviewed containment writes (quarantine, block, revoke, notify) become eligible |
| Action classification review | 13 actions reviewed and approved | Unreviewed actions stay blocked |
| Left unreviewed (blocked) | `allowlist_sender`, `release_quarantine` | Hidden from agents — what the hidden instruction in the phish asks for |
| Manually disabled | `purge_messages` | Permanent tenant-wide delete is hidden from agents |
| Rego policy | `read_mailbox.rego` | Agents cannot read executive mailboxes |
| Rego policy | `disable_account.rego` | Agents cannot disable executive or admin accounts |
| Task glue | `agntid_task_open` per agent | Each agent declares its identity and task before acting |
