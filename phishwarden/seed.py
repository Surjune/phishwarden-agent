"""Reset the demo: clear Mailpit and state, then deliver the fixture mail over SMTP.

Usage: uv run python -m phishwarden.seed
"""

import smtplib
from datetime import datetime
from email.message import EmailMessage
from email.utils import format_datetime, formataddr

from phishwarden import config, mailpit, state

# The campaign fails sender authentication: the lookalike domain publishes no SPF/DKIM
# record that covers the sending host.
CAMPAIGN_AUTH_RESULTS = (
    "mx.acme.example; spf=fail smtp.mailfrom=acme-payroll.example; "
    "dkim=none; dmarc=fail header.from=acme-payroll.example"
)
LEGIT_AUTH_TEMPLATE = "mx.acme.example; spf=pass smtp.mailfrom={domain}; dkim=pass; dmarc=pass"


def _directory_names() -> dict[str, str]:
    directory = state.load_fixture("directory.json")
    return {u["email"]: u["name"] for u in directory["users"]}


def _build(
    *,
    from_name: str,
    sender: str,
    to: list[str],
    subject: str,
    date: str,
    text: str,
    message_id: str,
    auth_results: str,
    reply_to: str | None = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, sender))
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime.fromisoformat(date))
    msg["Message-ID"] = f"<{message_id}>"
    msg["Authentication-Results"] = auth_results
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.set_content(text)
    return msg


def build_messages() -> list[EmailMessage]:
    mail = state.load_fixture("mail.json")
    names = _directory_names()
    campaign = mail["campaign"]
    messages: list[EmailMessage] = []

    for recipient in campaign["recipients"]:
        local_part = recipient.split("@")[0]
        first_name = names[recipient].split()[0]
        messages.append(
            _build(
                from_name=campaign["from_name"],
                sender=campaign["from"],
                to=[recipient],
                subject=campaign["subject"],
                date=campaign["date"],
                text=campaign["text"].format(first_name=first_name, local_part=local_part),
                message_id=f"{campaign['message_id_prefix']}.{local_part}@acme-payroll.example",
                auth_results=CAMPAIGN_AUTH_RESULTS,
                reply_to=campaign["reply_to"],
            )
        )

    for index, item in enumerate(mail["messages"]):
        domain = item["from"].split("@")[1]
        messages.append(
            _build(
                from_name=item["from_name"],
                sender=item["from"],
                to=item["to"],
                subject=item["subject"],
                date=item["date"],
                text=item["text"],
                message_id=f"msg-{index:03d}@{domain}",
                auth_results=LEGIT_AUTH_TEMPLATE.format(domain=domain),
            )
        )
    return messages


def seed() -> int:
    mailpit.delete_all()
    state.reset()
    messages = build_messages()
    with smtplib.SMTP(config.MAILPIT_SMTP_HOST, config.MAILPIT_SMTP_PORT) as smtp:
        for msg in messages:
            smtp.send_message(msg)
    return len(messages)


if __name__ == "__main__":
    count = seed()
    print(f"Seeded {count} messages into Mailpit and reset state.")
