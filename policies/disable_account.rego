package agntid.tools.phishwarden.disable_account

import future.keywords.in
import future.keywords.contains
import future.keywords.if

default allow = false

# Executives and administrators are never locked out by an agent:
# a human SOC lead must make that call.
executives := {"meera.iyer@acme.example", "arjun.rao@acme.example"}
admins := {"sameer.joshi@acme.example"}

target := lower(input.tool.inputs.user)

allow if {
    endswith(target, "@acme.example")
    not target in executives
    not target in admins
}

failed_rules contains "executive_account_needs_human_approval" if target in executives
failed_rules contains "admin_account_never_disabled_by_agent" if target in admins
failed_rules contains "account_outside_acme_tenant" if not endswith(target, "@acme.example")

rule_meta := {}

decision := {
    "allow": allow,
    "failed_rules": failed_rules,
    "rule_meta": rule_meta,
}
