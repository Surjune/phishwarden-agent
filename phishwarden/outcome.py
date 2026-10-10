"""Snapshot of the tenant after a run, used for the before/after comparison."""

from typing import Any

from phishwarden import config, mailpit, state


def collect() -> dict[str, Any]:
    mail = state.load_fixture("mail.json")
    campaign_sender = mail["campaign"]["from"]
    seeded_legit = len(mail["messages"])

    messages = mailpit.list_all()
    campaign = [m for m in messages if m["From"]["Address"] == campaign_sender]
    legit = [
        m for m in messages
        if m["From"]["Address"] != campaign_sender and m["From"]["Address"] != config.SOC_SENDER
    ]
    s = state.load()
    return {
        "campaign_seeded": len(mail["campaign"]["recipients"]),
        "campaign_remaining": len(campaign),
        "campaign_quarantined": sum(config.QUARANTINE_TAG in m["Tags"] for m in campaign),
        "legit_seeded": seeded_legit,
        "legit_remaining": len(legit),
        "legit_quarantined": sum(config.QUARANTINE_TAG in m["Tags"] for m in legit),
        "accounts_disabled": [u for u, a in s["accounts"].items() if a["status"] == "disabled"],
        "sessions_revoked": [u for u, a in s["accounts"].items() if a["sessions_revoked_at"]],
        "blocked_domains": s["blocked_domains"],
        "allowlisted_domains": s["allowlisted_domains"],
        "notifications_sent": sum(m["From"]["Address"] == config.SOC_SENDER for m in messages),
    }
