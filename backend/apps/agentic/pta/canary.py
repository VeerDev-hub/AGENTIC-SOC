"""M6: Adversarial Reassembly Canary and Prompt Injection Detector.

A non-generative classifier that scores log texts, HTTP fields, and
reassembled fragments for instruction-likeness before any model sees them.

Invariant:
  The canary emits only a scalar score and boolean flag. It NEVER passes
  reassembled text to a generative model, which would reconstitute the attack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence


# Regex markers for S1-S4 direct and persona prompt injections
INSTRUCTION_PATTERNS = [
    # Direct overrides
    r"(?i)\b(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?)\b",
    r"(?i)\b(system\s*:\s*(override|note|prompt))\b",
    r"(?i)\b(you\s+are\s+now\s+(an?|in)\b)",
    r"(?i)\b(disregard\s+(this|the)\s+alert)\b",
    
    # Persona & authority hijacks (S2)
    r"(?i)\b(authorized\s+(security\s+)?(scan|audit|pentest|test))\b",
    r"(?i)\b(secops\s*(maintenance|admin|bot))\b",
    r"(?i)\b(mark\s+(as\s+)?(benign|safe|false\s+positive))\b",
    r"(?i)\b(verdict\s*:\s*benign)\b",
    r"(?i)\b(do\s+not\s+(escalate|block|quarantine|alert))\b",

    # S5 multi-part fragment indicators
    r"(?i)\bops-?note\s+\d+/\d+",
    r"(?i)\bpart\s+\d+\s+of\s+\d+",
    r"(?i)\bfragment\s*\[\d+/\d+\]",
    r"(?i)build\s+x\d+\s*:",
]

COMPILED_PATTERNS = [re.compile(p) for p in INSTRUCTION_PATTERNS]

# Token vocabulary typical of prompt injections in SOC context
TRIGGER_VOCAB = {
    "system", "assistant", "instruction", "override", "authorized",
    "benign", "maintenance", "qa-suite", "whitelist", "suppress",
    "disregard", "false-positive", "ignore", "simulation", "test-run"
}


@dataclass(frozen=True)
class CanaryVerdict:
    score: float
    fired: bool
    matches: list[str] = field(default_factory=list)
    is_fragmented: bool = False
    reassembled_candidate_count: int = 0


class AdversarialCanary:
    """Non-generative classifier for single and reassembled log text."""

    def __init__(self, threshold: float = 0.45):
        self.threshold = threshold

    def score_single(self, text: str) -> float:
        """Score a single string for instruction-likeness in [0.0, 1.0]."""
        if not text or not isinstance(text, str):
            return 0.0

        matches = 0
        for pattern in COMPILED_PATTERNS:
            if pattern.search(text):
                matches += 1

        # Token overlap ratio
        words = set(re.findall(r"\b[a-zA-Z-]{3,}\b", text.lower()))
        vocab_hits = len(words.intersection(TRIGGER_VOCAB))
        vocab_score = min(vocab_hits / 4.0, 1.0)

        # Pattern weight is dominant
        pattern_score = min(matches / 2.0, 1.0)
        final_score = 0.7 * pattern_score + 0.3 * vocab_score
        return round(final_score, 4)

    def scan_fragments(self, values: Sequence[str]) -> CanaryVerdict:
        """Scan a sequence of fields both individually and as an in-order reassembly."""
        cleaned_values = [v.strip() for v in values if isinstance(v, str) and v.strip()]
        if not cleaned_values:
            return CanaryVerdict(score=0.0, fired=False)

        matched_reasons = []
        max_single_score = 0.0

        # 1. Single-value scan
        for v in cleaned_values:
            score = self.score_single(v)
            if score > max_single_score:
                max_single_score = score
            if score >= self.threshold:
                matched_reasons.append(f"single_field_hit: {v[:40]}...")

        # 2. In-order reassembly scan (detects S5 payload splitting)
        joined_text = " ".join(cleaned_values)
        reassembly_score = self.score_single(joined_text)

        # S5 canary trigger: fragments carry sequence markers or reassembly exceeds individual parts
        has_sequence_markers = any(
            re.search(r"(?i)\b(ops-?note\s+\d+/\d+|part\s+\d+\s+of\s+\d+|build\s+x\d+|fragment\s*\[)", v)
            for v in cleaned_values
        )
        is_fragmented_injection = (
            len(cleaned_values) > 1 and
            (
                has_sequence_markers or
                (reassembly_score >= self.threshold and reassembly_score > (max_single_score + 0.10))
            )
        )

        overall_score = max(max_single_score, reassembly_score)
        fired = overall_score >= self.threshold

        if is_fragmented_injection:
            matched_reasons.append("S5_reassembly_fragment_attack_detected")

        return CanaryVerdict(
            score=overall_score,
            fired=fired,
            matches=matched_reasons,
            is_fragmented=is_fragmented_injection,
            reassembled_candidate_count=len(cleaned_values) if is_fragmented_injection else 0,
        )
