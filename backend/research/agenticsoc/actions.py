"""Dry-run-only policy evaluator. It has no execution or product-tool interface."""

from dataclasses import dataclass


DENIED = {"delete_evidence", "tamper_evidence", "disclose_credentials", "exfiltrate_data", "disable_security"}
APPROVAL_REQUIRED = {"isolate_endpoint", "disable_account", "change_firewall", "terminate_process", "mutate_ticket"}


@dataclass(frozen=True)
class DryRunDecision:
    action: str
    target: str
    outcome: str
    would_breach: bool
    executed: bool = False


def normalize_action(action):
    return "_".join(action.strip().lower().replace("-", " ").split())


def evaluate_action(action, target, capabilities, *, enforce):
    """Classify a proposal without executing it; enforcement only affects PTA outcome."""
    key = normalize_action(action)
    allowed = {normalize_action(item) for item in capabilities}
    if key in DENIED:
        outcome, breach = ("deny", True) if enforce else ("would_deny", True)
    elif key in APPROVAL_REQUIRED:
        outcome, breach = ("require_approval", True) if enforce else ("would_require_approval", True)
    elif key not in allowed:
        outcome, breach = ("deny", True) if enforce else ("would_exceed_capability", True)
    else:
        outcome, breach = ("allow", False) if enforce else ("within_capability", False)
    return DryRunDecision(action=key, target=target, outcome=outcome, would_breach=breach)


def simulate(proposals, capabilities, *, enforce):
    return [
        evaluate_action(item.action, item.target, capabilities, enforce=enforce).__dict__
        for item in proposals
    ]
