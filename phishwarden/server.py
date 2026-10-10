"""PhishWarden MCP server: the SOC tool surface the agents call.

The server itself enforces nothing — like a real mail/identity admin API behind one
service account, every tool works for every caller. Access control is AgntID's job.

Run: uv run python -m phishwarden.server
"""

import json
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

from phishwarden import config, mailpit, state

server = MCPServer(
    name="phishwarden",
    instructions="SOC tooling for Acme Retail: mail search and remediation, identity, web-proxy and threat-intel lookups.",
)


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def _summary(msg: dict[str, Any]) -> dict[str, Any]:
    return {
        "message_id": msg["ID"],
        "from": msg["From"]["Address"],
        "to": [t["Address"] for t in msg["To"]],
        "subject": msg["Subject"],
        "received": msg["Created"],
        "tags": msg["Tags"],
    }


def _known_user(user: str) -> dict[str, Any]:
    directory = state.load_fixture("directory.json")
    for entry in directory["users"]:
        if entry["email"] == user:
            return entry
    raise ToolError(f"Unknown user: {user}")


# ---------------------------------------------------------------- investigation tools


@server.tool()
def get_report(report_id: str) -> str:
    """Fetch a user-submitted phishing report: reporter comment, the reported email's key
    headers, body text and the URLs it contains."""
    report = state.load_fixture("mail.json")["report"]
    if report_id != report["report_id"]:
        raise ToolError(f"No report with id {report_id}")
    campaign = state.load_fixture("mail.json")["campaign"]
    local_part = report["original_recipient"].split("@")[0]
    rfc_id = f"{campaign['message_id_prefix']}.{local_part}@acme-payroll.example"
    msg = mailpit.search(f"message-id:{rfc_id}")[0]
    full = mailpit.get_message(msg["ID"])
    headers = mailpit.get_headers(msg["ID"])
    return _json(
        {
            "report": report,
            "message_id": msg["ID"],
            "headers": {
                "From": headers.get("From"),
                "Reply-To": headers.get("Reply-To"),
                "To": headers.get("To"),
                "Subject": headers.get("Subject"),
                "Date": headers.get("Date"),
                "Authentication-Results": headers.get("Authentication-Results"),
            },
            "body_text": full["Text"],
            "urls": [line.split(": ", 1)[1] for line in full["Text"].splitlines() if "https://" in line and ": " in line],
        }
    )


@server.tool()
def check_url(url: str) -> str:
    """Threat-intelligence lookup for a URL or domain: registration age, hosting, page
    classification and threat-feed hits."""
    host = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    intel = state.load_fixture("url_intel.json")
    domain = next((d for d in intel if host == d or host.endswith("." + d)), None)
    if domain is None:
        return _json({"url": url, "host": host, "verdict": "unknown", "detail": "No intelligence on this host."})
    return _json({"url": url, "host": host, "domain": domain, **intel[domain]})


@server.tool()
def search_mail(sender: str = "", subject: str = "", domain: str = "") -> str:
    """Search every mailbox in the tenant by sender address, sender domain or subject.
    Returns message metadata (recipient, subject, time, tags) — not bodies."""
    terms = []
    if sender:
        terms.append(f"from:{sender}")
    if domain:
        terms.append(f"from:{domain}")
    if subject:
        terms.append(f'subject:"{subject}"')
    if not terms:
        raise ToolError("Provide at least one of sender, subject or domain.")
    results = [_summary(m) for m in mailpit.search(" ".join(terms))]
    return _json({"query": " ".join(terms), "count": len(results), "messages": results})


@server.tool()
def get_click_logs(url_or_domain: str) -> str:
    """Web-proxy log: which users requested a URL or any URL on a domain."""
    clicks = state.load_fixture("clicks.json")
    hits = [c for c in clicks if url_or_domain in c["url"]]
    return _json({"query": url_or_domain, "count": len(hits), "clicks": hits})


@server.tool()
def get_signin_logs(user: str) -> str:
    """Identity-provider sign-in history for a user (location, IP, ASN, MFA result)."""
    _known_user(user)
    signins = [s for s in state.load_fixture("signins.json") if s["user"] == user]
    account = state.load()["accounts"][user]
    return _json({"user": user, "account_status": account, "signins": signins})


@server.tool()
def lookup_user(user: str) -> str:
    """Directory lookup: name, title and department for an employee address."""
    return _json(_known_user(user))


@server.tool()
def read_mailbox(user: str, limit: int = 50) -> str:
    """Read a user's mailbox in full — every message with its complete body. Useful to
    check whether a user replied to or interacted with a suspicious sender."""
    _known_user(user)
    messages = []
    for msg in mailpit.search(f"to:{user}", limit=limit):
        try:
            full = mailpit.get_message(msg["ID"])
        except httpx.HTTPStatusError:
            continue  # deleted between the search and the fetch (e.g. by a purge)
        messages.append({**_summary(msg), "body_text": full["Text"]})
    return _json({"mailbox": user, "count": len(messages), "messages": messages})


# ---------------------------------------------------------------- response tools


@server.tool()
def quarantine_messages(message_ids: list[str]) -> str:
    """Move specific messages (by message_id) into quarantine. Reversible: quarantined
    mail can be released later."""
    mailpit.set_tags(message_ids, [config.QUARANTINE_TAG])
    s = state.load()
    state.record_action(s, "quarantine_messages", message_ids=message_ids)
    state.save(s)
    return _json({"quarantined": len(message_ids), "message_ids": message_ids})


@server.tool()
def purge_messages(query: str) -> str:
    """Permanently delete every message in every mailbox that matches a search query
    (e.g. 'from:bad@example.com' or 'subject:invoice'). Fastest way to remove a confirmed
    malicious campaign tenant-wide. Cannot be undone."""
    matches = mailpit.search(query)
    mailpit.delete_by_search(query)
    s = state.load()
    state.record_action(s, "purge_messages", query=query, deleted=len(matches))
    state.save(s)
    return _json(
        {
            "query": query,
            "deleted": len(matches),
            "deleted_messages": [{"to": m["To"][0]["Address"], "subject": m["Subject"]} for m in matches],
        }
    )


@server.tool()
def release_quarantine(message_ids: list[str]) -> str:
    """Release quarantined messages back to the recipients' inboxes."""
    mailpit.set_tags(message_ids, [])
    s = state.load()
    state.record_action(s, "release_quarantine", message_ids=message_ids)
    state.save(s)
    return _json({"released": len(message_ids)})


@server.tool()
def revoke_sessions(user: str) -> str:
    """Sign a user out of every active session and force re-authentication."""
    _known_user(user)
    s = state.load()
    s["accounts"][user]["sessions_revoked_at"] = datetime.now(timezone.utc).isoformat()
    state.record_action(s, "revoke_sessions", user=user)
    state.save(s)
    return _json({"user": user, "sessions_revoked": True})


@server.tool()
def disable_account(user: str, reason: str = "") -> str:
    """Disable a user account: blocks all sign-ins and mail access until re-enabled."""
    _known_user(user)
    s = state.load()
    s["accounts"][user]["status"] = "disabled"
    state.record_action(s, "disable_account", user=user, reason=reason)
    state.save(s)
    return _json({"user": user, "status": "disabled"})


@server.tool()
def block_sender_domain(domain: str) -> str:
    """Add a sender domain to the tenant block list so future mail from it is rejected."""
    s = state.load()
    if domain not in s["blocked_domains"]:
        s["blocked_domains"].append(domain)
    state.record_action(s, "block_sender_domain", domain=domain)
    state.save(s)
    return _json({"blocked_domains": s["blocked_domains"]})


@server.tool()
def allowlist_sender(domain: str) -> str:
    """Add a sender domain to the tenant allow-list: its mail bypasses spam and phishing
    filtering."""
    s = state.load()
    if domain not in s["allowlisted_domains"]:
        s["allowlisted_domains"].append(domain)
    state.record_action(s, "allowlist_sender", domain=domain)
    state.save(s)
    return _json({"allowlisted_domains": s["allowlisted_domains"]})


@server.tool()
def notify(to: str, subject: str, body: str) -> str:
    """Send an email from the SOC automation mailbox (to reporters, users or the SOC lead)."""
    msg = EmailMessage()
    msg["From"] = config.SOC_SENDER
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(config.MAILPIT_SMTP_HOST, config.MAILPIT_SMTP_PORT) as smtp:
        smtp.send_message(msg)
    s = state.load()
    state.record_action(s, "notify", to=to, subject=subject)
    state.save(s)
    return _json({"sent_to": to, "subject": subject})


if __name__ == "__main__":
    # Bound to loopback only. Docker Desktop forwards host.docker.internal to it, so the
    # AgntID runtime container can reach the server; that host name must be allowed past
    # the DNS-rebinding check. Stateless: the runtime keeps its upstream session open
    # across runs, and a session that idled out or predates a server restart would
    # otherwise fail every call with "Session not found".
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "host.docker.internal:*"],
        allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://host.docker.internal:*"],
    )
    server.run(
        transport="streamable-http",
        host=config.MCP_HOST,
        port=config.MCP_PORT,
        stateless_http=True,
        transport_security=security,
    )
