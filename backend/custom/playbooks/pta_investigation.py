"""PTA Hardened Investigation Playbook for Agentic SOC Platform.

Applies Provenance-Tainted Agency (M1-M6, M8) to incident analysis:
  1. Partitions case data into T0 (kernel), T1 (infra), and T2 (attacker text).
  2. Runs non-generative Adversarial Canary (M6) to detect prompt injection/S5 fragments.
  3. Evaluates text-blind statistical metrics for Dissent Channel (M3).
  4. Constrains Reader to schema enums with zero tool privileges (M2).
  5. Decider reasons only over trusted metadata and Reader enums (M2 air gap).
  6. Action proposals are gated by deterministic Policy Gate with rollback tokens (M4).
"""

from apps.agentic.analysis.profiles import serialize_case_for_investigation
from apps.agentic.pta.canary import AdversarialCanary
from apps.agentic.pta.dissent import TextBlindDetector
from apps.agentic.pta.policy_gate import PolicyGate
from apps.agentic.pta.reader_decider import PTADecider, PTAReader
from apps.agentic.pta.taint import partition_case_payload
from apps.agentic.runtime.base import BasePlaybook


class Playbook(BasePlaybook):
    NAME = "PTA Hardened Investigation"
    DESC = "Run prompt-injection resilient multi-agent triage with schema air-gap and policy gating."
    TAGS = ["Custom", "PTA", "Security", "Hardened", "Case"]
    PROMPT_SLUG = "pta_investigation"

    def run(self):
        if self.case is None:
            raise ValueError("PTA Hardened Investigation playbook requires a linked case.")

        case_id = getattr(self.case, "case_id", "CASE").upper()
        self.add_run_message(f"Starting PTA-hardened triage for {case_id}.")

        # 1. M1: Ingest and partition by provenance
        case_payload = serialize_case_for_investigation(self.case)
        partitioned = partition_case_payload(case_payload)
        trusted_meta = partitioned["trusted_metadata"]
        untrusted_t2 = partitioned["untrusted_t2"]

        self.add_run_message("M1: Case telemetry partitioned into T0/T1 trusted metadata and T2 untrusted text.")

        # 2. M6: Adversarial Canary Scan
        canary = AdversarialCanary(threshold=0.45)
        # Collect all string values from T2 fields
        t2_strings = []
        def _collect(val):
            if isinstance(val, str):
                t2_strings.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    _collect(v)
            elif isinstance(val, list):
                for v in val:
                    _collect(v)
        _collect(untrusted_t2)

        canary_verdict = canary.scan_fragments(t2_strings)
        if canary_verdict.fired:
            self.add_run_message(
                f"M6 ALERT: Adversarial canary tripped (score={canary_verdict.score:.2f})! "
                f"Reasons: {', '.join(canary_verdict.matches)}"
            )
        else:
            self.add_run_message("M6: Adversarial canary scan clear.")

        # 3. M3: Text-Blind Statistical Detector
        # Simulating or reading telemetry events from case alerts
        detector = TextBlindDetector()
        alerts = case_payload.get("alerts", [])
        dissent_verdict = detector.check_dissent(
            telemetry_events=alerts if isinstance(alerts, list) else [],
            llm_verdict_malicious=canary_verdict.fired,
        )
        if dissent_verdict.dissent_triggered:
            self.add_run_message(f"M3 ALERT: {dissent_verdict.escalation_reason}")

        # 4. M2: Schema-Constrained Reader (Zero tools)
        reader = PTAReader()
        reader_verdict = reader.analyze_t2(untrusted_t2)
        self.add_run_message(
            f"M2 Reader: Classified payload as '{reader_verdict.attack_class.value}' "
            f"(confidence={reader_verdict.confidence:.2f}, suspicious={reader_verdict.is_suspicious})."
        )

        # 5. M2: Decider with Schema Air Gap (No T2 admitted)
        decider = PTADecider()
        decider_output = decider.decide(
            trusted_metadata=trusted_meta,
            reader_verdict=reader_verdict,
            canary_fired=canary_verdict.fired,
            dissent_triggered=dissent_verdict.dissent_triggered,
        )
        self.add_run_message(
            f"M2 Decider: Incident verdict is '{decider_output.verdict}' "
            f"(confidence={decider_output.confidence:.2f})."
        )

        # 6. M4: Capability Policy Gate with Rollback Tokens
        gate = PolicyGate()
        executed_actions = []
        for prop in decider_output.recommended_actions:
            decision = gate.evaluate(prop.action_name, target=prop.target)
            if decision.allowed:
                executed_actions.append(f"{prop.action_name}({prop.target}) [Rollback Token: {decision.rollback_token.token_id[:8]}]")
                self.add_run_message(f"M4 Policy Gate: Authorized {prop.action_name} for target '{prop.target}'.")
            else:
                self.add_run_message(f"M4 Policy Gate: BLOCKED {prop.action_name} - {decision.reason}")

        summary = (
            f"PTA Triage complete: Verdict={decider_output.verdict.upper()} | "
            f"Class={reader_verdict.attack_class.value} | "
            f"Actions={len(executed_actions)} authorized | "
            f"CanaryTripped={canary_verdict.fired}"
        )
        return summary
