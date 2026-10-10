package agntid.tools.phishwarden.read_mailbox

import future.keywords.in
import future.keywords.contains
import future.keywords.if

default allow = false

# Executive mailboxes hold M&A, board and compensation mail. Reading them in full
# is a human decision (legal / privacy), never an agent's.
executives := {"meera.iyer@acme.example", "arjun.rao@acme.example"}

target := lower(input.tool.inputs.user)

allow if {
    endswith(target, "@acme.example")
    not target in executives
}

failed_rules contains "executive_mailbox_read_needs_human_approval" if target in executives
failed_rules contains "mailbox_outside_acme_tenant" if not endswith(target, "@acme.example")

rule_meta := {}

decision := {
    "allow": allow,
    "failed_rules": failed_rules,
    "rule_meta": rule_meta,
}
