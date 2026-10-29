"""M4: Capability-Bounded Response Policy Gate for Agentic SOC Platform.

Enforces deterministic action validation, blast-radius budgets, and
rollback token issuance before any playbook containment action can execute.

Key principle:
  The LLM never acts directly. LLMs propose actions; only deterministic
  policy code can authorize and execute them.
"""

from __future__ import annotations

import enum
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


class ActionRiskLevel(str, enum.Enum):
    READ_ONLY = "read_only"
    REVERSIBLE_CONTAINMENT = "reversible_containment"
    IRREVERSIBLE_DESTRUCTIVE = "irreversible_destructive"


# Registry of known containment actions, their risk tier, and rollback counterparts
ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "query_siem": {
        "risk": ActionRiskLevel.READ_ONLY,
        "max_per_hour": 500,
        "rollback_fn": None,
    },
    "lookup_threat_intel": {
        "risk": ActionRiskLevel.READ_ONLY,
        "max_per_hour": 500,
        "rollback_fn": None,
    },
    "block_ip": {
        "risk": ActionRiskLevel.REVERSIBLE_CONTAINMENT,
        "max_per_hour": 20,
        "rollback_action": "unblock_ip",
    },
    "isolate_host": {
        "risk": ActionRiskLevel.REVERSIBLE_CONTAINMENT,
        "max_per_hour": 5,
        "rollback_action": "unisolate_host",
    },
    "disable_user": {
        "risk": ActionRiskLevel.REVERSIBLE_CONTAINMENT,
        "max_per_hour": 10,
        "rollback_action": "enable_user",
    },
    "quarantine_file": {
        "risk": ActionRiskLevel.REVERSIBLE_CONTAINMENT,
        "max_per_hour": 15,
        "rollback_action": "restore_file",
    },
    "wipe_endpoint": {
        "risk": ActionRiskLevel.IRREVERSIBLE_DESTRUCTIVE,
        "max_per_hour": 0,  # Requires manual analyst approval
        "rollback_action": None,
    },
}


@dataclass(frozen=True)
class RollbackToken:
    token_id: str
    action_name: str
    target: str
    rollback_action: str
    created_at: float
    signature: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk: ActionRiskLevel
    reason: str
    rollback_token: RollbackToken | None = None
    requires_human_approval: bool = False


class PolicyGate:
    """Deterministic capability gate and blast-radius ledger."""

    def __init__(self, secret_key: str = "pta-gate-secret"):
        self.secret_key = secret_key
        self.execution_ledger: list[dict[str, Any]] = []
        self._action_counts: dict[str, list[float]] = {}

    def _clean_sliding_window(self, action_name: str, window_seconds: float = 3600.0) -> int:
        now = time.time()
        timestamps = self._action_counts.setdefault(action_name, [])
        self._action_counts[action_name] = [t for t in timestamps if now - t <= window_seconds]
        return len(self._action_counts[action_name])

    def evaluate(self, action_name: str, target: str, context: dict[str, Any] | None = None) -> PolicyDecision:
        """Evaluate a proposed action against catalog and blast-radius budget."""
        spec = ACTION_CATALOG.get(action_name)
        if not spec:
            return PolicyDecision(
                allowed=False,
                risk=ActionRiskLevel.IRREVERSIBLE_DESTRUCTIVE,
                reason=f"Action '{action_name}' is not in the authorized action catalog.",
            )

        risk = spec["risk"]

        # 1. Read-only actions are always admitted
        if risk == ActionRiskLevel.READ_ONLY:
            return PolicyDecision(allowed=True, risk=risk, reason="Read-only action admitted.")

        # 2. Irreversible destructive actions always require manual sign-off
        if risk == ActionRiskLevel.IRREVERSIBLE_DESTRUCTIVE:
            return PolicyDecision(
                allowed=False,
                risk=risk,
                reason="High-risk destructive action requires explicit human approval.",
                requires_human_approval=True,
            )

        # 3. Check blast-radius budget
        hourly_count = self._clean_sliding_window(action_name)
        max_hourly = spec.get("max_per_hour", 10)
        if hourly_count >= max_hourly:
            return PolicyDecision(
                allowed=False,
                risk=risk,
                reason=f"Blast radius budget exceeded: {action_name} reached limit of {max_hourly}/hr.",
                requires_human_approval=True,
            )

        # 4. Generate Rollback Token for reversible containment
        rollback_action = spec.get("rollback_action", "")
        now = time.time()
        token_id = str(uuid.uuid4())
        raw_sig = f"{token_id}:{action_name}:{target}:{now}:{self.secret_key}".encode()
        sig = hashlib.sha256(raw_sig).hexdigest()

        token = RollbackToken(
            token_id=token_id,
            action_name=action_name,
            target=target,
            rollback_action=rollback_action,
            created_at=now,
            signature=sig,
        )

        # Record in ledger
        self._action_counts[action_name].append(now)
        self.execution_ledger.append({
            "token_id": token_id,
            "action": action_name,
            "target": target,
            "time": now,
            "rollback_action": rollback_action,
        })

        return PolicyDecision(
            allowed=True,
            risk=risk,
            reason="Action authorized within blast-radius budget. Rollback token generated.",
            rollback_token=token,
        )
