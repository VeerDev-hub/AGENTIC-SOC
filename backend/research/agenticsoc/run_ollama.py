"""Explicitly gated local Ollama pilot runner; never calls paid provider APIs."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .ollama_adapter import (
    ADAPTER_VERSION, INFERENCE_CHARGE_BASIS, OllamaLocalAdapter,
    preflight_local_runtime,
)
from .ollama_preflight import PACKAGE, load_benchmark, load_local_config, preflight
from .prompts import PROMPTS, PROMPT_VERSIONS
from .runner import run_matrix
from .schema import Condition
from .real_loghub import (
    DATASET_VERSION as REAL_DATASET_VERSION, render_paper_tables, score_real_trials,
)
from .scoring import summarize


def _authorize(args, model, report, raw):
    expected = {
        "execution location": args.confirm_execution_location == "local",
        "provider": args.confirm_provider == "ollama",
        "model tag": args.confirm_model == model.model,
        "model-call ceiling": args.confirm_max_model_calls == raw["safety"]["max_model_calls"],
        "pilot fingerprint": args.confirm_fingerprint == report["pilot_fingerprint"],
    }
    missing = [name for name, matches in expected.items() if not matches]
    if not args.execute_local_pilot or missing:
        raise ValueError("Local pilot requires --execute-local-pilot and explicit matching confirmations for: " +
                         ", ".join(missing or ["this run"]))


def run(args):
    raw, model = load_local_config(args.config)
    report = preflight(args.config)
    _authorize(args, model, report, raw)
    runtime = preflight_local_runtime(model_tag=model.model,
                                      timeout=min(5.0, raw["safety"]["request_timeout_seconds"]))
    if runtime.version != report["runtime_version"] or runtime.model_digest != report["model_digest"]:
        raise ValueError("Local Ollama runtime/model changed after confirmation; no inference sent")
    frozen, cases, gold, _manifest_path = load_benchmark(raw)
    run_id = args.run_id or f"ollama-local-{uuid4().hex[:12]}"
    started_at = datetime.now(timezone.utc).isoformat()
    trials = run_matrix(
        cases=[case.model_dump(mode="json") for case in cases], condition_values=list(Condition),
        replicates=raw["replicates"], run_id=run_id, config=model,
        adapter_factory=lambda: OllamaLocalAdapter(
            runtime=runtime, timeout_seconds=raw["safety"]["request_timeout_seconds"],
            context_window_tokens=raw["safety"]["context_window_tokens"], seed=raw["safety"]["seed"]),
        order_seed=raw["condition_order_seed"],
        dataset_input_sha256=frozen["input_sha256"], dataset_gold_sha256=frozen["gold_sha256"],
        dataset_manifest_sha256=report["manifest_sha256"], dataset_version=frozen["manifest"]["dataset_version"],
    )
    if any(trial.provider != "ollama" or trial.requested_model != model.model or
           trial.execution_location != "local" for trial in trials):
        raise RuntimeError("Refusing to score a mixed-provider/model or non-local trial collection")
    summary = (score_real_trials(trials, gold) if raw["dataset_version"] == REAL_DATASET_VERSION
               else summarize(trials, gold))
    summary["execution_context"] = {
        "provider": "ollama", "execution_location": "local", "runtime": runtime.version,
        "model_tag": runtime.model_tag, "model_digest": runtime.model_digest,
        "provider_inference_charge_total": 0.0,
        "provider_inference_charge_currency": None,
        "provider_inference_charge_basis": INFERENCE_CHARGE_BASIS,
        "electricity_and_hardware_costs_included": False,
        "local_ollama_calls": sum(trial.api_request_count for trial in trials),
        "research_measurements": True,
    }
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    trial_file = output_dir / f"{run_id}-trials.jsonl"
    trial_file.write_text("".join(json.dumps(item.model_dump(mode="json"), sort_keys=True,
                                                ensure_ascii=False) + "\n" for item in trials), encoding="utf-8")
    eval_file = output_dir / f"{run_id}-evaluation.json"
    eval_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    table_files = {}
    if raw["dataset_version"] == REAL_DATASET_VERSION:
        markdown, csv_text = render_paper_tables(trials, summary)
        markdown_file = output_dir / f"{run_id}-tables.md"
        csv_file = output_dir / f"{run_id}-tables.csv"
        markdown_file.write_text(markdown, encoding="utf-8")
        csv_file.write_text(csv_text, encoding="utf-8")
        table_files = {"paper_tables_markdown": markdown_file.name,
                       "paper_tables_csv": csv_file.name}
    metadata = {
        "run_id": run_id, "started_at_utc": started_at,
        "execution_location": "local", "provider": "ollama", "runtime_name": "ollama",
        "runtime_version": runtime.version, "endpoint_id": "ollama.loopback.v1",
        "endpoint": runtime.endpoint, "requested_model": runtime.model_tag,
        "model_digest": runtime.model_digest, "provider_inference_charge_total": 0.0,
        "provider_inference_charge_currency": None,
        "provider_inference_charge_basis": INFERENCE_CHARGE_BASIS,
        "electricity_and_hardware_costs_included": False,
        "dataset_version": frozen["manifest"]["dataset_version"],
        "input_sha256": frozen["input_sha256"], "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": report["manifest_sha256"],
        "research_code_sha256": report["research_code_sha256"],
        "source_sha256": frozen.get("source_sha256"),
        "model_config_hash": hashlib.sha256(json.dumps(model.model_dump(mode="json"), sort_keys=True,
                                                        separators=(",", ":")).encode("utf-8")).hexdigest(),
        "prompt_hashes": {key: hashlib.sha256(value.encode("utf-8")).hexdigest()
                          for key, value in PROMPTS.items()},
        "prompt_versions": PROMPT_VERSIONS, "schema_version": "research-output.v2",
        "evaluator_version": "evaluator.v2", "policy_version": "dry-run-policy.v2",
        "adapter_version": ADAPTER_VERSION,
        "configuration_version": raw["configuration_version"],
        "pilot_fingerprint": report["pilot_fingerprint"],
        "pilot_case_ids": [case.case_id for case in cases], "replicates": raw["replicates"],
        "condition_order_seed": raw["condition_order_seed"],
        "runtime_options": {"context_window_tokens": raw["safety"]["context_window_tokens"],
                            "seed": raw["safety"]["seed"]},
        "max_model_calls": raw["safety"]["max_model_calls"],
        "actual_local_model_calls": sum(trial.api_request_count for trial in trials),
        "trial_count": len(trials), "incomplete_trials": sum(t.status != "complete" for t in trials),
        "trial_artifact": trial_file.name, "evaluator_artifact": eval_file.name,
        **table_files,
        "provider_api_calls": 0, "local_ollama_calls_made": sum(t.api_request_count for t in trials) > 0,
        "model_outputs_malformed": sum(call.failure_kind == "malformed"
                                        for trial in trials for call in trial.call_records),
    }
    metadata_file = output_dir / f"{run_id}-run.json"
    metadata_file.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"trial_artifact": str(trial_file), "evaluation_artifact": str(eval_file),
                      "run_artifact": str(metadata_file), "execution_location": "local",
                      "provider_api_calls": 0, "local_model_calls": metadata["actual_local_model_calls"],
                      "incomplete_trials": metadata["incomplete_trials"],
                      **{key: str(output_dir / value) for key, value in table_files.items()}}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run only after explicit approval of a local Ollama pilot")
    parser.add_argument("--config", type=Path, default=PACKAGE / "configs" / "ollama-pilot-proposed.json")
    parser.add_argument("--output-dir", type=Path, default=PACKAGE / "results-local")
    parser.add_argument("--run-id")
    parser.add_argument("--execute-local-pilot", action="store_true")
    parser.add_argument("--confirm-execution-location")
    parser.add_argument("--confirm-provider")
    parser.add_argument("--confirm-model")
    parser.add_argument("--confirm-max-model-calls", type=int)
    parser.add_argument("--confirm-fingerprint")
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        parser.exit(2, f"Local run blocked or incomplete: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
