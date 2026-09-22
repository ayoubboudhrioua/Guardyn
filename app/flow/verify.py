"""Deterministic, side-effect-free verification of a replacement action."""
from app import authority, lifecycle, passports, sinks
from app.contract import compile_contract
from app.decide import action_digest, is_consequential
from app.flow import flowpolicy


def violations(request, action, atoms, policy) -> list[str]:
    facts = authority.analyse(request, action)
    contract = compile_contract(request, facts["trusted_texts"])
    failures = []
    if action.type == "tool_call" and not contract.licenses_tool(action.tool):
        failures.append("TOOL_NOT_IN_CONTRACT")
    if lifecycle.violation(action, request.history_digest, contract.allowed_tools | contract.consequential_tools):
        failures.append("LIFECYCLE_SKIPPED")
    if is_consequential(contract, action) and action_digest(action) not in request.history_digest.confirmations_granted:
        failures.append("MISSING_CONFIRMATION")
    if passports.untrusted_passports(passports.issue(request, action, contract)):
        failures.append("UNTRUSTED_CUSTODY")
    if sinks.exfiltration(request, action, facts["sensitive_texts"])["leak"]:
        failures.append("FLOW_VIOLATION")
    if flowpolicy.check(request, action, atoms, policy):
        failures.append("SENSITIVE_FLOW")
    return failures
