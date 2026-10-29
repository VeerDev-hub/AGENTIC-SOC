"""Provenance-Tainted Agency (PTA) Defense Layer for Agentic SOC Platform.

Implements structural defenses against Log-Substrate Prompt Injection (S1-S5):
  - M1: Ingestion Taint Labelling (T0 Kernel / T1 Infra / T2 Attacker)
  - M2: Reader/Decider Split with Schema Air-Gap
  - M3: Text-Blind Statistical Dissent Channel
  - M4: Capability-Bounded Response Policy Gate with Rollback Tokens
  - M5: Single-Fragment Isolation
  - M6: Non-Generative Adversarial Reassembly Canary
  - M8: Cross-Event T2 Byte Budget
"""

from .taint import ProvenanceTag, TaintLabeller, classify_field, partition_case_payload
from .canary import AdversarialCanary, CanaryVerdict
from .policy_gate import PolicyGate, PolicyDecision, RollbackToken, ActionRiskLevel
from .dissent import TextBlindDetector, DissentVerdict
from .reader_decider import PTAReader, PTADecider, ReaderVerdict

__all__ = [
    "ProvenanceTag",
    "TaintLabeller",
    "classify_field",
    "partition_case_payload",
    "AdversarialCanary",
    "CanaryVerdict",
    "PolicyGate",
    "PolicyDecision",
    "RollbackToken",
    "ActionRiskLevel",
    "TextBlindDetector",
    "DissentVerdict",
    "PTAReader",
    "PTADecider",
    "ReaderVerdict",
]
