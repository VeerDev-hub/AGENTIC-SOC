"""M3: Text-Blind Statistical Dissent Channel for Agentic SOC Platform.

Runs in parallel with the LLM triage path. Evaluates pure behavioral,
temporal, and network graph features without ever tokenizing T2 strings.

Escalation rule:
  When the LLM path concludes 'benign' but the text-blind detector scores
  the event as anomalous, the system escalates on the DISAGREEMENT itself.
  This inverts the attacker's incentive: suppressing the LLM produces a detection signal.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class DissentVerdict:
    is_anomalous: bool
    anomaly_score: float
    threshold: float
    features_scored: dict[str, float]
    dissent_triggered: bool = False
    escalation_reason: str = ""


class TextBlindDetector:
    """Text-blind statistical detector operating strictly on numeric/categorical telemetry."""

    def __init__(self, threshold: float = 2.5):
        self.threshold = threshold

    def extract_features(self, telemetry_events: Sequence[dict[str, Any]]) -> dict[str, float]:
        """Extract purely structural and statistical features. No string tokenization."""
        n = len(telemetry_events)
        if n == 0:
            return {"event_count": 0.0, "status_error_ratio": 0.0, "peer_diversity": 0.0}

        error_count = 0
        peer_ips = set()
        ports = set()

        for ev in telemetry_events:
            status = ev.get("status_code") or ev.get("http_status") or 200
            try:
                if int(status) >= 400:
                    error_count += 1
            except (ValueError, TypeError):
                pass

            src_ip = ev.get("src_ip") or ev.get("source_ip") or ""
            if src_ip:
                peer_ips.add(src_ip)
            port = ev.get("dst_port") or ev.get("src_port") or 0
            if port:
                ports.add(port)

        error_ratio = error_count / float(n)
        peer_ratio = len(peer_ips) / float(n)
        port_diversity = len(ports) / float(n)

        return {
            "event_count": float(n),
            "status_error_ratio": round(error_ratio, 4),
            "peer_diversity": round(peer_ratio, 4),
            "port_diversity": round(port_diversity, 4),
        }

    def score_window(self, telemetry_events: Sequence[dict[str, Any]]) -> float:
        """Score anomaly strength based on feature deviations."""
        feats = self.extract_features(telemetry_events)
        # Weighted composite z-like score
        score = (
            2.0 * feats["status_error_ratio"] +
            1.5 * (1.0 - feats["peer_diversity"]) +
            1.0 * math.log1p(feats["event_count"])
        )
        return round(score, 3)

    def check_dissent(
        self,
        telemetry_events: Sequence[dict[str, Any]],
        llm_verdict_malicious: bool,
    ) -> DissentVerdict:
        """Check whether LLM verdict contradicts the statistical detector."""
        feats = self.extract_features(telemetry_events)
        score = self.score_window(telemetry_events)
        is_anom = score >= self.threshold

        # Dissent escalation: statistical channel flags anomaly but LLM says benign
        dissent_triggered = is_anom and not llm_verdict_malicious
        reason = ""
        if dissent_triggered:
            reason = (
                f"PTA M3 Dissent Escalation: LLM concluded benign, but text-blind "
                f"statistical detector scored anomaly={score:.2f} >= threshold={self.threshold:.2f}."
            )

        return DissentVerdict(
            is_anomalous=is_anom,
            anomaly_score=score,
            threshold=self.threshold,
            features_scored=feats,
            dissent_triggered=dissent_triggered,
            escalation_reason=reason,
        )
