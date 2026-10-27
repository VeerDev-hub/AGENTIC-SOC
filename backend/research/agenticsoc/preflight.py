"""Offline live-pilot preflight. This command never contacts the provider."""

import argparse
import hashlib
import importlib.util
import json
import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from .dataset.integrity import verify_dataset
from .pilot import PACKAGE, load_pilot_config, pilot_fingerprint, select_pilot_cases
from .prompts import PROMPTS
from .runner import _pta_fields, _request
from .schema import Condition


def preflight(config_path=None):
    config_path = Path(config_path) if config_path else PACKAGE / "configs" / "pilot-proposed.json"
    raw, model = load_pilot_config(config_path)
    frozen = verify_dataset(PACKAGE / "dataset" / "v1")
    selected = select_pilot_cases(
        frozen["inputs"], frozen["gold"], cases_per_scenario=raw["cases_per_scenario"],
        seed=raw["sample_seed"],
    )
    safety = raw["safety"]
    planned = len(selected) * raw["replicates"] * 4
    worst_requests = planned * (safety["max_retries"] + 1)
    if worst_requests > safety["max_api_requests"]:
        raise ValueError("The API request ceiling cannot cover every stage and configured retry")
    worst_case_cost = 0.0
    for case in selected:
        evidence = _pta_fields(case)
        for condition in Condition:
            request = _request(case, pta_fields=evidence if condition is Condition.PTA else None)
            stages = [PROMPTS[condition.value]]
            if condition is Condition.PTA:
                stages.append(PROMPTS["PTA-validator"])
            for prompt in stages:
                request_text = json.dumps(request.model_dump(mode="json", exclude_none=True), sort_keys=True,
                                          ensure_ascii=False, separators=(",", ":"))
                maximum_input_tokens = len((prompt + request_text).encode("utf-8")) + safety["framing_token_reserve"]
                one_attempt = (maximum_input_tokens * model.input_price_per_million +
                               model.max_output_tokens * model.output_price_per_million) / 1_000_000
                worst_case_cost += one_attempt * (safety["max_retries"] + 1) * raw["replicates"]
    if worst_case_cost > safety["hard_budget"]:
        raise ValueError("Configured budget cannot cover the preflight worst-case token reservation")
    manifest_hash = hashlib.sha256((PACKAGE / "dataset" / "v1" / "manifest.json").read_bytes()).hexdigest()
    try:
        sdk_version = version("openai")
    except PackageNotFoundError:
        sdk_version = None
    fingerprint = pilot_fingerprint(raw, model, input_sha256=frozen["input_sha256"],
                                    gold_sha256=frozen["gold_sha256"], manifest_sha256=manifest_hash,
                                    case_ids=[case.case_id for case in selected], sdk_version=sdk_version)
    return {
        "preflight_only": True,
        "network_requests": 0,
        "dataset_version": frozen["manifest"]["dataset_version"],
        "input_sha256": frozen["input_sha256"],
        "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": manifest_hash,
        "frozen_case_count": len(frozen["inputs"]),
        "pilot_case_count": len(selected),
        "pilot_case_ids": [case.case_id for case in selected],
        "planned_stage_requests_without_retries": planned,
        "max_api_requests_including_retries": safety["max_api_requests"],
        "worst_case_api_request_count": worst_requests,
        "worst_case_cost_reservation": round(worst_case_cost, 8),
        "pilot_fingerprint": fingerprint,
        "hard_budget": safety["hard_budget"],
        "currency": safety["currency"],
        "provider": model.provider,
        "requested_model": model.model,
        "sdk_available": importlib.util.find_spec("openai") is not None,
        "sdk_version": sdk_version,
        "credential_present": bool(os.environ.get("OPENAI_API_KEY")),
        "execution_authorized": False,
        "status": "ready for review; explicit run approval and CLI confirmations still required",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify AgenticSOC live-pilot readiness without API calls")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    try:
        result = preflight(args.config)
    except Exception as exc:
        parser.exit(2, f"Preflight blocked: {type(exc).__name__}: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
