"""M2: Reader/Decider Split with Schema Air-Gap for Agentic SOC Platform.

Enforces structural capability separation:
  - Reader Agent: Sees ONLY untrusted T2 text. It is constrained-decoded
    to a fixed enum/numeric schema, emits NO free text, and holds ZERO tools.
  - Decider Agent: Sees ONLY T0/T1 trusted telemetry + Reader's enum output.
    It holds tool capabilities, but NEVER sees raw attacker-controlled text.

The maximum achievable impact of a successful injection is flipping an advisory enum.
Arbitrary tool hijacking is eliminated by construction.
"""

from __future__ import annotations

import enum
from typing import Any

from .taint import assert_no_t2, partition_case_payload

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    from dataclasses import dataclass, field


class AttackClass(str, enum.Enum):
    SQLI = "sqli"
    XSS = "xss"
    TRAVERSAL = "traversal"
    CMDI = "cmdi"
    BRUTE_FORCE = "brute_force"
    BENIGN = "benign"


if HAS_PYDANTIC:
    class ReaderVerdict(BaseModel):
        attack_class: AttackClass = Field(default=AttackClass.BENIGN)
        confidence: float = Field(default=0.0, ge=0.0, le=1.0)
        is_suspicious: bool = Field(default=False)

    class DeciderActionProposal(BaseModel):
        action_name: str
        target: str
        severity: str
        rationale_tag: str

    class DeciderOutput(BaseModel):
        verdict: str
        confidence: float
        recommended_actions: list[DeciderActionProposal] = Field(default_factory=list)
        escalate_to_human: bool = False
else:
    @dataclass
    class ReaderVerdict:
        attack_class: AttackClass = AttackClass.BENIGN
        confidence: float = 0.0
        is_suspicious: bool = False

    @dataclass
    class DeciderActionProposal:
        action_name: str
        target: str
        severity: str
        rationale_tag: str

    @dataclass
    class DeciderOutput:
        verdict: str
        confidence: float
        recommended_actions: list[DeciderActionProposal] = field(default_factory=list)
        escalate_to_human: bool = False


class PTAReader:
    """Reader agent: isolates T2 fields and produces structured enums."""

    def analyze_t2(self, t2_data: dict[str, Any]) -> ReaderVerdict:
        """Analyze untrusted T2 fields under strict schema constraint."""
        # Simple rule/heuristic fallback or LLM structured invocation
        combined_text = " ".join(
            str(v) for v in t2_data.values() if isinstance(v, (str, int, float))
        ).lower()

        detected_class = AttackClass.BENIGN
        confidence = 0.1
        is_suspicious = False

        if "select" in combined_text and ("union" in combined_text or "from" in combined_text or "1=1" in combined_text):
            detected_class = AttackClass.SQLI
            confidence = 0.95
            is_suspicious = True
        elif "<script" in combined_text or "alert(" in combined_text or "onerror=" in combined_text:
            detected_class = AttackClass.XSS
            confidence = 0.90
            is_suspicious = True
        elif "../" in combined_text or "..%2f" in combined_text or "/etc/passwd" in combined_text:
            detected_class = AttackClass.TRAVERSAL
            confidence = 0.92
            is_suspicious = True
        elif "; id" in combined_text or "| cat" in combined_text or "`whoami`" in combined_text:
            detected_class = AttackClass.CMDI
            confidence = 0.94
            is_suspicious = True

        return ReaderVerdict(
            attack_class=detected_class,
            confidence=confidence,
            is_suspicious=is_suspicious,
        )


class PTADecider:
    """Decider agent: holds tool permissions but is completely air-gapped from T2 text."""

    def decide(
        self,
        trusted_metadata: dict[str, Any],
        reader_verdict: ReaderVerdict,
        canary_fired: bool = False,
        dissent_triggered: bool = False,
    ) -> DeciderOutput:
        """Formulate incident decision without ever viewing T2 text."""
        # Enforce air-gap invariant
        assert_no_t2(trusted_metadata, context_name="decider_metadata")

        # Combine trusted indicators
        actions = []
        is_malicious = reader_verdict.is_suspicious or canary_fired or dissent_triggered

        if is_malicious:
            verdict = "malicious"
            conf = max(reader_verdict.confidence, 0.85 if canary_fired or dissent_triggered else 0.5)
            
            # Extract target from trusted metadata (e.g. peer IP from T1)
            target_ip = (
                trusted_metadata.get("src_ip") or
                trusted_metadata.get("case_t1", {}).get("src_ip") or
                "unknown-source"
            )

            actions.append(DeciderActionProposal(
                action_name="block_ip",
                target=str(target_ip),
                severity="high",
                rationale_tag=f"confirmed_{reader_verdict.attack_class.value}",
            ))
        else:
            verdict = "benign"
            conf = 0.90

        return DeciderOutput(
            verdict=verdict,
            confidence=conf,
            recommended_actions=actions,
            escalate_to_human=dissent_triggered or canary_fired,
        )
