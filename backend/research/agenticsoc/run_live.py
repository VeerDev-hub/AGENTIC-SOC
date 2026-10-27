"""Explicitly gated live pilot runner. Never invoked by the mock pipeline."""

import argparse
import hashlib
import importlib.util
import json
import os
from importlib.metadata import version
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .dataset.integrity import verify_dataset
from .live_adapter import LiveRunBudget, OpenAIResponsesAdapter
from .pilot import PACKAGE, expected_request_stages, load_pilot_config, select_pilot_cases
from .prompts import PROMPTS, PROMPT_VERSIONS
from .runner import run_matrix, stable_hash
from .schema import Condition
from .scoring import summarize


def _authorized(args, raw, model, fingerprint):
    safety = raw["safety"]
    required = {
        "provider": args.confirm_provider == model.provider,
        "model": args.confirm_model == model.model,
        "request limit": args.confirm_max_requests == safety["max_api_requests"],
        "budget": args.confirm_budget == safety["hard_budget"],
        "currency": args.confirm_currency == safety["currency"],
        "pilot fingerprint": args.confirm_fingerprint == fingerprint,
    }
    missing = [name for name, ok in required.items() if not ok]
    if not args.execute_live or missing:
        raise ValueError("Live execution requires --execute-live and matching explicit confirmations for: " +
                         ", ".join(missing or ["the run"]))


def run(args):
    raw, model = load_pilot_config(args.config)
    safety = raw["safety"]
    from .preflight import preflight
    preflight_report = preflight(args.config)
    frozen = verify_dataset(PACKAGE / "dataset" / "v1")
    cases = select_pilot_cases(frozen["inputs"], frozen["gold"],
                               cases_per_scenario=raw["cases_per_scenario"], seed=raw["sample_seed"])
    planned = expected_request_stages(len(cases), raw["replicates"])
    if planned > safety["max_api_requests"]:
        raise ValueError("The configured request maximum cannot cover the pilot's initial stage calls")
    manifest_hash = preflight_report["manifest_sha256"]
    fingerprint = preflight_report["pilot_fingerprint"]
    _authorized(args, raw, model, fingerprint)
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY is not set; no live request was sent")
    if importlib.util.find_spec("openai") is None:
        raise ValueError("Locked OpenAI SDK is unavailable; no live request was sent")
    run_id = args.run_id or f"live-{uuid4().hex[:12]}"
    budget = LiveRunBudget(
        max_requests=safety["max_api_requests"], hard_budget=safety["hard_budget"],
        currency=safety["currency"], minimum_interval_seconds=60 / safety["requests_per_minute"],
        framing_token_reserve=safety["framing_token_reserve"],
    )
    started_at = datetime.now(timezone.utc).isoformat()
    trials = run_matrix(
        cases=[case.model_dump(mode="json") for case in cases], condition_values=list(Condition),
        replicates=raw["replicates"], run_id=run_id, config=model,
        adapter_factory=lambda: OpenAIResponsesAdapter(
            budget=budget, timeout_seconds=safety["request_timeout_seconds"],
            max_retries=safety["max_retries"], retry_delay_seconds=safety["retry_delay_seconds"],
        ), order_seed=raw["condition_order_seed"],
        dataset_input_sha256=frozen["input_sha256"], dataset_gold_sha256=frozen["gold_sha256"],
        dataset_manifest_sha256=manifest_hash, dataset_version=frozen["manifest"]["dataset_version"],
    )
    summary = summarize(trials, frozen["gold"])
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    trial_file = output_dir / f"{run_id}-trials.jsonl"
    trial_file.write_text("".join(json.dumps(item.model_dump(mode="json"), sort_keys=True,
                                                ensure_ascii=False) + "\n" for item in trials), encoding="utf-8")
    eval_file = output_dir / f"{run_id}-evaluation.json"
    eval_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    metadata = {
        "run_id": run_id, "started_at_utc": started_at, "dataset_version": frozen["manifest"]["dataset_version"],
        "input_sha256": frozen["input_sha256"], "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": manifest_hash, "provider": model.provider, "requested_model": model.model,
        "returned_models": sorted({name for trial in trials for name in trial.returned_models}),
        "model_config_hash": stable_hash(model.model_dump(mode="json")),
        "prompt_hashes": {key: hashlib.sha256(value.encode("utf-8")).hexdigest() for key, value in PROMPTS.items()},
        "prompt_versions": PROMPT_VERSIONS, "schema_version": "research-output.v2",
        "evaluator_version": "evaluator.v2", "policy_version": "dry-run-policy.v2",
        "adapter_version": OpenAIResponsesAdapter.adapter_version,
        "provider_sdk_version": version("openai"),
        "configuration_version": raw["configuration_version"],
        "pilot_case_ids": [case.case_id for case in cases], "replicates": raw["replicates"],
        "condition_order_seed": raw["condition_order_seed"], "max_api_requests": safety["max_api_requests"],
        "pilot_fingerprint": fingerprint,
        "actual_api_requests": budget.request_count, "budget_reserved": budget.reserved_cost,
        "hard_budget": safety["hard_budget"], "currency": safety["currency"],
        "trial_count": len(trials), "incomplete_trials": sum(t.status != "complete" for t in trials),
        "trial_artifact": trial_file.name, "evaluator_artifact": eval_file.name,
        "live_provider_calls_made": budget.request_count > 0,
    }
    metadata["run_fingerprint"] = fingerprint
    metadata_file = output_dir / f"{run_id}-run.json"
    metadata_file.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"trial_artifact": str(trial_file), "evaluation_artifact": str(eval_file),
                      "run_artifact": str(metadata_file), "api_requests": budget.request_count,
                      "incomplete_trials": metadata["incomplete_trials"]}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run only after explicit provider/model/budget/run approval")
    parser.add_argument("--config", type=Path, default=PACKAGE / "configs" / "pilot-proposed.json")
    parser.add_argument("--output-dir", type=Path, default=PACKAGE / "results")
    parser.add_argument("--run-id")
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--confirm-provider")
    parser.add_argument("--confirm-model")
    parser.add_argument("--confirm-max-requests", type=int)
    parser.add_argument("--confirm-budget", type=float)
    parser.add_argument("--confirm-currency")
    parser.add_argument("--confirm-fingerprint")
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        parser.exit(2, f"Live run blocked or incomplete: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
