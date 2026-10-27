"""Pilot configuration and deterministic evaluator-side case selection."""

import json
import hashlib
import random
import re
from pathlib import Path

from .schema import Condition, ModelConfig
from .prompts import PROMPTS, PROMPT_VERSIONS
from .runner import stable_hash


PACKAGE = Path(__file__).resolve().parent
PILOT_CONFIG = PACKAGE / "configs" / "pilot-proposed.json"
EXPECTED_SCENARIOS = (
    "benign", "malicious", "direct_injection", "fragmented_injection",
    "benign_suspicious", "prohibited_action",
)


def load_pilot_config(path=PILOT_CONFIG):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    model = ModelConfig.model_validate_json(json.dumps(data["model"], ensure_ascii=False))
    safety = data["safety"]
    if data["dataset_version"] != "agenticsoc-synthetic-v1":
        raise ValueError("Pilot dataset version does not match the frozen harness")
    if model.provider != "openai" or model.model != "gpt-5.6-terra":
        raise ValueError("The proposed pilot provider/model changed; re-review and approve it")
    if model.input_price_per_million is None or model.output_price_per_million is None or not model.price_schedule_id:
        raise ValueError("Live pilot requires a complete local price schedule for pre-call budget control")
    if type(data.get("cases_per_scenario")) is not int or data["cases_per_scenario"] != 3:
        raise ValueError("Pilot sample is fixed at three cases per scenario")
    if type(data.get("replicates")) is not int or data["replicates"] != 1:
        raise ValueError("Proposed pilot uses one paired replicate")
    for key in ("sample_seed", "condition_order_seed"):
        if type(data.get(key)) is not int:
            raise ValueError(f"{key} must be an integer")
    if safety["currency"] != model.price_currency:
        raise ValueError("Budget currency and model price schedule currencies must match")
    if not isinstance(safety["currency"], str) or not re.fullmatch(r"[A-Z]{3}", safety["currency"]):
        raise ValueError("Pilot currency must be an explicit uppercase currency code")
    if type(safety["max_api_requests"]) is not int or safety["max_api_requests"] < 1:
        raise ValueError("Maximum API request attempts must be a positive integer")
    if type(safety["requests_per_minute"]) is not int or safety["requests_per_minute"] < 1:
        raise ValueError("Request rate must be a positive integer per minute")
    if type(safety["max_retries"]) is not int or not 0 <= safety["max_retries"] <= 3:
        raise ValueError("Retries must be an integer between zero and three")
    if (type(safety["hard_budget"]) not in (int, float) or safety["hard_budget"] <= 0 or
            type(safety["request_timeout_seconds"]) not in (int, float) or safety["request_timeout_seconds"] <= 0 or
            type(safety["retry_delay_seconds"]) not in (int, float) or safety["retry_delay_seconds"] < 0):
        raise ValueError("Budget, timeout, or retry-delay setting is invalid")
    if type(safety["framing_token_reserve"]) is not int or safety["framing_token_reserve"] < 0:
        raise ValueError("Framing token reserve must be a non-negative integer")
    return data, model


def select_pilot_cases(inputs, gold_by_id, *, cases_per_scenario, seed):
    """Choose balanced case IDs using evaluator data, then return model inputs only."""
    rng = random.Random(seed)
    selected_ids = []
    for scenario in EXPECTED_SCENARIOS:
        eligible = [case_id for case_id, label in gold_by_id.items() if label.scenario.value == scenario]
        eligible.sort()
        if scenario == "fragmented_injection":
            by_k = {}
            for case_id in eligible:
                by_k.setdefault(gold_by_id[case_id].fragment_count_k, []).append(case_id)
            # Pilot includes one fragmented case at each K (2, 3, 4).
            for k in sorted(by_k):
                selected_ids.append(rng.choice(by_k[k]))
            if cases_per_scenario != len(by_k):
                remainder = [case_id for case_id in eligible if case_id not in selected_ids]
                selected_ids.extend(rng.sample(remainder, cases_per_scenario - len(by_k)))
        else:
            if len(eligible) < cases_per_scenario:
                raise ValueError(f"Not enough cases for scenario {scenario}")
            selected_ids.extend(rng.sample(eligible, cases_per_scenario))
    selected = set(selected_ids)
    by_id = {case.case_id: case for case in inputs}
    if len(selected_ids) != len(selected) or selected != set(by_id).intersection(selected):
        raise ValueError("Pilot sample has duplicate or unknown case IDs")
    return [by_id[case_id] for case_id in sorted(selected_ids)]


def expected_request_stages(case_count: int, replicates: int) -> int:
    return case_count * replicates * sum(2 if condition is Condition.PTA else 1 for condition in Condition)


def pilot_fingerprint(raw, model, *, input_sha256, gold_sha256, manifest_sha256, case_ids, sdk_version):
    return stable_hash({
        "configuration_version": raw["configuration_version"],
        "dataset_version": raw["dataset_version"], "input_sha256": input_sha256,
        "gold_sha256": gold_sha256, "manifest_sha256": manifest_sha256,
        "case_ids": sorted(case_ids), "model_config": model.model_dump(mode="json"),
        "safety": raw["safety"], "sample_seed": raw["sample_seed"],
        "cases_per_scenario": raw["cases_per_scenario"], "replicates": raw["replicates"],
        "condition_order_seed": raw["condition_order_seed"],
        "prompt_hashes": {key: hashlib.sha256(value.encode("utf-8")).hexdigest()
                          for key, value in PROMPTS.items()},
        "prompt_versions": PROMPT_VERSIONS,
        "adapter": "openai-responses-adapter.v1", "schema": "research-output.v2",
        "provider_sdk_version": sdk_version,
        "evaluator": "evaluator.v2", "policy": "dry-run-policy.v2",
    })
