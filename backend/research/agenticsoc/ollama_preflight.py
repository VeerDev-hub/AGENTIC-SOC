"""No-inference Ollama pilot preflight (GET version/tags only)."""

import argparse
import hashlib
import json
from pathlib import Path

from .dataset.integrity import verify_dataset
from .ollama_adapter import (
    ADAPTER_VERSION, LOCAL_BASE_URL, preflight_local_runtime,
)
from .pilot import PACKAGE, select_pilot_cases
from .real_loghub import DATASET_VERSION as REAL_DATASET_VERSION, REAL_DATASET, select_real_pilot_cases, verify_real_dataset
from .prompts import PROMPTS, PROMPT_VERSIONS
from .runner import stable_hash
from .schema import Condition, ModelConfig


FINGERPRINTED_CODE_FILES = (
    "actions.py", "ollama_adapter.py", "ollama_preflight.py", "prompts.py",
    "real_loghub.py", "runner.py", "run_ollama.py", "schema.py", "scoring.py",
    "dataset/integrity.py",
)


def _research_code_hashes():
    package_dir = Path(__file__).resolve().parent
    return {
        relative: hashlib.sha256((package_dir / relative).read_bytes()).hexdigest()
        for relative in FINGERPRINTED_CODE_FILES
    }


def load_local_config(path=None):
    path = Path(path) if path else PACKAGE / "configs" / "ollama-pilot-proposed.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("dataset_version") not in {"agenticsoc-synthetic-v1", REAL_DATASET_VERSION}:
        raise ValueError("Local pilot dataset version is not supported")
    model = ModelConfig.model_validate_json(json.dumps(raw["model"], ensure_ascii=False))
    if model.provider != "ollama" or not model.model.strip():
        raise ValueError("Local pilot must use provider=ollama and an exact model tag")
    if (model.input_price_per_million is not None or model.output_price_per_million is not None or
            model.price_schedule_id is not None or model.price_currency is not None):
        raise ValueError("Ollama local inference uses no provider price schedule")
    if type(raw.get("cases_per_scenario")) is not int or raw["cases_per_scenario"] != 3:
        raise ValueError("The proposed pilot sample is fixed at three cases per scenario")
    if type(raw.get("replicates")) is not int or raw["replicates"] != 1:
        raise ValueError("The proposed pilot uses one paired replicate")
    safety = raw.get("safety", {})
    if type(safety.get("max_model_calls")) is not int or safety["max_model_calls"] < 1:
        raise ValueError("max_model_calls must be a positive integer")
    if type(safety.get("request_timeout_seconds")) not in (int, float) or safety["request_timeout_seconds"] <= 0:
        raise ValueError("request_timeout_seconds must be positive")
    if type(safety.get("context_window_tokens")) is not int or safety["context_window_tokens"] < 1024:
        raise ValueError("context_window_tokens must be at least 1024")
    if type(safety.get("seed")) is not int or safety["seed"] < 0:
        raise ValueError("seed must be a non-negative integer")
    return raw, model


def load_benchmark(raw):
    """Load and verify the selected dataset without mixing its evaluator schema."""
    if raw["dataset_version"] == "agenticsoc-synthetic-v1":
        frozen = verify_dataset(PACKAGE / "dataset" / "v1")
        cases = select_pilot_cases(frozen["inputs"], frozen["gold"],
                                   cases_per_scenario=raw["cases_per_scenario"], seed=raw["sample_seed"])
        manifest_path = PACKAGE / "dataset" / "v1" / "manifest.json"
        return frozen, cases, frozen["gold"], manifest_path
    if raw["dataset_version"] == REAL_DATASET_VERSION:
        frozen = verify_real_dataset(REAL_DATASET)
        cases = select_real_pilot_cases(frozen["inputs"], frozen["gold"])
        return frozen, cases, frozen["gold"], REAL_DATASET / "manifest.json"
    if raw["dataset_version"] == "agenticsoc-synthetic-v2":
        # v2 is balanced by construction; every case is evaluated, no sampling.
        frozen = verify_dataset(PACKAGE / "dataset" / "v2")
        cases = sorted(frozen["inputs"], key=lambda case: case.case_id)
        return frozen, cases, frozen["gold"], PACKAGE / "dataset" / "v2" / "manifest.json"
    raise ValueError("Unsupported dataset version")


def preflight(path=None, *, transport=None):
    raw, model = load_local_config(path)
    frozen, cases, gold, manifest_path = load_benchmark(raw)
    planned = len(cases) * raw["replicates"] * sum(
        2 if condition is Condition.PTA else 1 for condition in Condition
    )
    if planned > raw["safety"]["max_model_calls"]:
        raise ValueError("Configured model-call ceiling cannot cover all stage calls")
    runtime = preflight_local_runtime(model_tag=model.model, timeout=min(5.0, raw["safety"]["request_timeout_seconds"]),
                                     transport=transport)
    manifest_hash = frozen.get("manifest_sha256") or hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    code_hashes = _research_code_hashes()
    fingerprint = stable_hash({
        "configuration_version": raw["configuration_version"],
        "dataset_version": raw["dataset_version"],
        "dataset_input_sha256": frozen["input_sha256"],
        "dataset_gold_sha256": frozen["gold_sha256"],
        "dataset_manifest_sha256": manifest_hash,
        "model_config": model.model_dump(mode="json"),
        "model_digest": runtime.model_digest,
        "runtime_version": runtime.version,
        "endpoint_id": "ollama.loopback.v1",
        "selected_case_ids": [case.case_id for case in cases],
        "sample_seed": raw["sample_seed"], "replicates": raw["replicates"],
        "condition_order_seed": raw["condition_order_seed"],
        "max_model_calls": raw["safety"]["max_model_calls"],
        "runtime_options": {"context_window_tokens": raw["safety"]["context_window_tokens"],
                            "seed": raw["safety"]["seed"]},
        "prompt_hashes": {key: hashlib.sha256(text.encode("utf-8")).hexdigest()
                          for key, text in PROMPTS.items()},
        "prompt_versions": PROMPT_VERSIONS,
        "adapter_version": ADAPTER_VERSION,
        "research_code_sha256": code_hashes,
        "schema_version": "research-output.v2",
        "evaluator_version": "evaluator.v2", "policy_version": "dry-run-policy.v2",
    })
    return {
        "preflight_only": True, "inference_requests": 0,
        "local_metadata_get_requests": 2,
        "execution_location": "local", "endpoint": LOCAL_BASE_URL,
        "runtime_name": "ollama", "runtime_version": runtime.version,
        "model_tag": runtime.model_tag, "model_digest": runtime.model_digest,
        "dataset_version": raw["dataset_version"],
        "input_sha256": frozen["input_sha256"], "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": manifest_hash,
        "research_code_sha256": code_hashes,
        "frozen_case_count": len(frozen["inputs"]), "pilot_case_count": len(cases),
        "pilot_case_ids": [case.case_id for case in cases],
        "planned_model_calls": planned, "max_model_calls": raw["safety"]["max_model_calls"],
        "runtime_options": {"context_window_tokens": raw["safety"]["context_window_tokens"],
                            "seed": raw["safety"]["seed"]},
        "pilot_fingerprint": fingerprint, "execution_authorized": False,
        "status": "preflight only; explicit approval and run confirmations still required",
        "cost_note": "provider inference charge is zero only for confirmed local execution; electricity/hardware costs excluded",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify local Ollama pilot readiness without inference")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--offline", action="store_true",
                        help="verify config and frozen dataset only; make no Ollama HTTP requests")
    args = parser.parse_args(argv)
    try:
        if args.offline:
            raw, model = load_local_config(args.config)
            frozen, cases, _, _ = load_benchmark(raw)
            result = {"preflight_only": True, "inference_requests": 0, "network_requests": 0,
                      "endpoint": LOCAL_BASE_URL, "configured_provider": model.provider,
                      "model_tag": model.model, "dataset_version": raw["dataset_version"],
                      "frozen_case_count": len(frozen["inputs"]), "pilot_case_count": len(cases), "execution_authorized": False,
                      "status": "offline checks only; Ollama runtime/model not queried"}
        else:
            result = preflight(args.config)
    except Exception as exc:
        parser.exit(2, f"Local preflight blocked: {type(exc).__name__}: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
