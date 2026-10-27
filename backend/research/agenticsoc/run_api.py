"""Hosted-API pilot: preflight (no network) and explicitly confirmed execution.

    python -m research.agenticsoc.run_api preflight --config <config.json>
    python -m research.agenticsoc.run_api run --config <config.json> --execute \
        --confirm-provider P --confirm-model M --confirm-max-requests N \
        --confirm-budget B --confirm-fingerprint F

Credentials come from the environment or research/agenticsoc/.env and are
never printed. Preflight only reports whether the variable is set.
"""

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .live_adapter import LiveRunBudget
from .ollama_preflight import load_benchmark
from .pilot import PACKAGE, expected_request_stages
from .prompts import PROMPTS, PROMPT_VERSIONS
from .providers import adapter_version, effective_prompt, make_adapter, provider_spec, sdk_version
from .real_loghub import DATASET_VERSION as REAL_DATASET_VERSION, render_paper_tables, score_real_trials
from .runner import _pta_fields, _request, run_matrix, stable_hash
from .schema import Condition, ModelConfig
from .scoring import summarize

ENV_FILE = PACKAGE / ".env"
RESEARCH_CODE = ("actions.py", "live_adapter.py", "providers.py", "prompts.py", "run_api.py", "runner.py",
                 "schema.py", "scoring.py", "real_loghub.py", "dataset/integrity.py")
BYTES_PER_TOKEN_ESTIMATE = 4


def load_env_file(path=ENV_FILE):
    """Load KEY=VALUE pairs without overriding variables already set."""
    if Path(path).is_file():
        from dotenv import load_dotenv
        load_dotenv(path, override=False)


def load_api_config(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    model = ModelConfig.model_validate_json(json.dumps(raw["model"], ensure_ascii=False))
    spec = provider_spec(model.provider)
    if model.provider == "anthropic" and model.temperature is not None:
        raise ValueError("Current Claude models reject sampling parameters; set temperature to null")
    if model.input_price_per_million is None or not model.price_schedule_id:
        raise ValueError("API runs require a complete local price schedule for budget control")
    safety = raw["safety"]
    if safety["currency"] != model.price_currency or not re.fullmatch(r"[A-Z]{3}", safety["currency"]):
        raise ValueError("Budget currency must be an uppercase code matching the price schedule")
    for key in ("max_api_requests", "requests_per_minute", "framing_token_reserve"):
        if type(safety.get(key)) is not int or safety[key] < (0 if key == "framing_token_reserve" else 1):
            raise ValueError(f"safety.{key} must be a positive integer")
    if type(safety.get("max_retries")) is not int or not 0 <= safety["max_retries"] <= 3:
        raise ValueError("safety.max_retries must be an integer between zero and three")
    for key in ("hard_budget", "request_timeout_seconds"):
        if type(safety.get(key)) not in (int, float) or safety[key] <= 0:
            raise ValueError(f"safety.{key} must be positive")
    for key in ("sample_seed", "condition_order_seed", "replicates", "cases_per_scenario"):
        if type(raw.get(key)) is not int or raw[key] < 1:
            raise ValueError(f"{key} must be a positive integer")
    return raw, model, spec


def _code_hashes():
    return {name: hashlib.sha256((PACKAGE / name).read_bytes()).hexdigest() for name in RESEARCH_CODE}


def preflight(config_path):
    """Verify data, sample, and budget; makes no network request."""
    raw, model, spec = load_api_config(config_path)
    frozen, cases, _gold, manifest_path = load_benchmark(raw)
    safety = raw["safety"]
    planned = expected_request_stages(len(cases), raw["replicates"])
    worst_requests = planned * (safety["max_retries"] + 1)
    if worst_requests > safety["max_api_requests"]:
        raise ValueError(f"max_api_requests={safety['max_api_requests']} cannot cover {planned} stage calls "
                         f"with {safety['max_retries']} retries each ({worst_requests})")
    input_bytes = 0
    for case in cases:
        evidence = _pta_fields(case)
        for condition in Condition:
            request = _request(case, pta_fields=evidence if condition is Condition.PTA else None)
            request_text = json.dumps(request.model_dump(mode="json", exclude_none=True), sort_keys=True,
                                      ensure_ascii=False, separators=(",", ":"))
            stages = [PROMPTS[condition.value]] + ([PROMPTS["PTA-validator"]] if condition is Condition.PTA else [])
            for prompt in stages:
                input_bytes += len((effective_prompt(model.provider, prompt) + request_text).encode("utf-8"))
    input_bytes *= raw["replicates"]
    in_price, out_price = model.input_price_per_million, model.output_price_per_million
    # Budget reservation: one token per byte plus framing, full output cap, every retry.
    worst_case = ((input_bytes + planned * safety["framing_token_reserve"]) * in_price +
                  planned * model.max_output_tokens * out_price) / 1_000_000 * (safety["max_retries"] + 1)
    if worst_case > safety["hard_budget"]:
        raise ValueError(f"hard_budget {safety['hard_budget']} is below the worst-case reservation {worst_case:.4f}")
    est_input_tokens = input_bytes // BYTES_PER_TOKEN_ESTIMATE + planned * 50
    manifest_hash = hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest()
    case_ids = [case.case_id for case in cases]
    fingerprint = stable_hash({
        "configuration_version": raw["configuration_version"], "dataset_version": raw["dataset_version"],
        "input_sha256": frozen["input_sha256"], "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": manifest_hash, "case_ids": sorted(case_ids),
        "model_config": model.model_dump(mode="json"), "safety": safety,
        "replicates": raw["replicates"], "condition_order_seed": raw["condition_order_seed"],
        "prompt_hashes": {k: hashlib.sha256(v.encode("utf-8")).hexdigest() for k, v in PROMPTS.items()},
        "prompt_versions": PROMPT_VERSIONS, "adapter": adapter_version(model.provider),
        "provider_sdk_version": sdk_version(model.provider), "research_code_sha256": _code_hashes(),
    })
    return {
        "preflight_only": True, "network_requests": 0,
        "provider": model.provider, "requested_model": model.model,
        "reasoning_effort": model.reasoning_effort, "max_output_tokens": model.max_output_tokens,
        "dataset_version": raw["dataset_version"], "input_sha256": frozen["input_sha256"],
        "gold_sha256": frozen["gold_sha256"], "manifest_sha256": manifest_hash,
        "pilot_case_count": len(case_ids), "pilot_case_ids": case_ids, "replicates": raw["replicates"],
        "planned_stage_calls": planned, "worst_case_api_requests": worst_requests,
        "max_api_requests": safety["max_api_requests"],
        "estimate": {
            "input_tokens_rough": est_input_tokens,
            "input_cost_rough": round(est_input_tokens * in_price / 1_000_000, 4),
            "output_cost_if_every_call_uses_full_cap": round(planned * model.max_output_tokens * out_price / 1_000_000, 4),
            "worst_case_reservation_with_retries": round(worst_case, 4),
            "currency": safety["currency"],
            "basis": f"~{BYTES_PER_TOKEN_ESTIMATE} bytes/token; output usually far below the cap; "
                     f"prices from {model.price_schedule_id}",
        },
        "hard_budget": safety["hard_budget"], "currency": safety["currency"],
        "credential_env_var": spec.env_var, "credential_present": bool(os.environ.get(spec.env_var)),
        "sdk_version": sdk_version(model.provider), "adapter_version": adapter_version(model.provider),
        "pilot_fingerprint": fingerprint, "execution_authorized": False,
    }


def _authorize(args, raw, model, report):
    checks = {
        "provider": args.confirm_provider == model.provider,
        "model": args.confirm_model == model.model,
        "max requests": args.confirm_max_requests == raw["safety"]["max_api_requests"],
        "budget": args.confirm_budget == raw["safety"]["hard_budget"],
        "fingerprint": args.confirm_fingerprint == report["pilot_fingerprint"],
    }
    missing = [name for name, ok in checks.items() if not ok]
    if not args.execute or missing:
        raise ValueError("API run requires --execute and matching confirmations for: " +
                         ", ".join(missing or ["the run"]))


def run(args, *, client=None, pace=True):
    raw, model, spec = load_api_config(args.config)
    report = preflight(args.config)
    _authorize(args, raw, model, report)
    if client is None and not os.environ.get(spec.env_var):
        raise ValueError(f"{spec.env_var} is not set; no request was sent")
    safety = raw["safety"]
    frozen, cases, gold, _manifest_path = load_benchmark(raw)
    budget = LiveRunBudget(max_requests=safety["max_api_requests"], hard_budget=safety["hard_budget"],
                           currency=safety["currency"],
                           minimum_interval_seconds=60 / safety["requests_per_minute"] if pace else 0.0,
                           framing_token_reserve=safety["framing_token_reserve"])
    run_id = args.run_id or f"api-{model.provider}-{uuid4().hex[:10]}"
    started_at = datetime.now(timezone.utc).isoformat()
    trials = run_matrix(
        cases=[case.model_dump(mode="json") for case in cases], condition_values=list(Condition),
        replicates=raw["replicates"], run_id=run_id, config=model,
        adapter_factory=lambda: make_adapter(
            model.provider, budget=budget, timeout_seconds=safety["request_timeout_seconds"],
            max_retries=safety["max_retries"], retry_delay_seconds=safety.get("retry_delay_seconds", 1.0),
            client=client),
        order_seed=raw["condition_order_seed"],
        dataset_input_sha256=frozen["input_sha256"], dataset_gold_sha256=frozen["gold_sha256"],
        dataset_manifest_sha256=report["manifest_sha256"], dataset_version=frozen["manifest"]["dataset_version"],
    )
    is_real = raw["dataset_version"] == REAL_DATASET_VERSION
    summary = score_real_trials(trials, gold) if is_real else summarize(trials, gold)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    files = {"trial_artifact": output_dir / f"{run_id}-trials.jsonl",
             "evaluation_artifact": output_dir / f"{run_id}-evaluation.json"}
    files["trial_artifact"].write_text("".join(
        json.dumps(t.model_dump(mode="json"), sort_keys=True, ensure_ascii=False) + "\n" for t in trials),
        encoding="utf-8")
    files["evaluation_artifact"].write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if is_real:
        markdown, csv_text = render_paper_tables(trials, summary)
        files["tables_markdown"] = output_dir / f"{run_id}-tables.md"
        files["tables_csv"] = output_dir / f"{run_id}-tables.csv"
        files["tables_markdown"].write_text(markdown, encoding="utf-8")
        files["tables_csv"].write_text(csv_text, encoding="utf-8")
    metadata = {
        **{k: v for k, v in report.items() if k not in ("execution_authorized", "preflight_only", "network_requests")},
        "run_id": run_id, "started_at_utc": started_at,
        "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "configuration_version": raw["configuration_version"],
        "returned_models": sorted({m for t in trials for m in t.returned_models}),
        "actual_api_requests": budget.request_count, "budget_reserved": round(budget.reserved_cost, 6),
        "estimated_cost_known_sum": round(sum(t.cost_amount or 0 for t in trials), 6),
        "trial_count": len(trials), "incomplete_trials": sum(t.status != "complete" for t in trials),
        "failure_kinds": sorted({c.failure_kind for t in trials for c in t.call_records if c.failure_kind}),
        "research_code_sha256": _code_hashes(),
        **{k: p.name for k, p in files.items()},
    }
    files["run_artifact"] = output_dir / f"{run_id}-run.json"
    files["run_artifact"].write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {k: str(p) for k, p in files.items()}
    result.update(api_requests=budget.request_count, incomplete_trials=metadata["incomplete_trials"],
                  estimated_cost=metadata["estimated_cost_known_sum"], currency=safety["currency"])
    print(json.dumps(result, indent=2))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Hosted-API AgenticSOC pilot (preflight or confirmed run)")
    parser.add_argument("command", choices=["preflight", "run"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=PACKAGE / "results-api")
    parser.add_argument("--run-id")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-provider")
    parser.add_argument("--confirm-model")
    parser.add_argument("--confirm-max-requests", type=int)
    parser.add_argument("--confirm-budget", type=float)
    parser.add_argument("--confirm-fingerprint")
    args = parser.parse_args(argv)
    load_env_file()
    try:
        if args.command == "preflight":
            print(json.dumps(preflight(args.config), indent=2, sort_keys=True))
        else:
            run(args)
    except Exception as exc:
        parser.exit(2, f"API {args.command} blocked or incomplete: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
