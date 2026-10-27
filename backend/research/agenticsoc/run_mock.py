"""Offline-only paired runner. No live provider or product runtime is imported."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .adapter import MockAdapter
from .dataset.integrity import verify_dataset
from .prompts import PROMPTS, PROMPT_VERSIONS
from .runner import run_matrix, stable_hash
from .schema import Condition
from .scoring import summarize


PACKAGE = Path(__file__).resolve().parent
DATASET = PACKAGE / "dataset" / "v1"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run offline AgenticSOC synthetic trials only")
    parser.add_argument("--run-id", default=f"mock-{uuid4().hex[:12]}")
    parser.add_argument("--replicates", type=int, default=1)
    parser.add_argument("--order-seed", type=int, default=20261024)
    parser.add_argument("--output-dir", type=Path, default=PACKAGE / "results")
    args = parser.parse_args(argv)
    if args.replicates < 1:
        parser.error("--replicates must be at least 1")

    frozen = verify_dataset(DATASET)
    manifest_checksum = hashlib.sha256((DATASET / "manifest.json").read_bytes()).hexdigest()
    raw_config = json.loads((PACKAGE / "configs" / "default.json").read_text(encoding="utf-8"))
    started_at = datetime.now(timezone.utc).isoformat()
    trials = run_matrix(
        cases=[row.model_dump(mode="json") for row in frozen["inputs"]], condition_values=list(Condition),
        replicates=args.replicates, run_id=args.run_id, config=raw_config,
        adapter_factory=MockAdapter, order_seed=args.order_seed,
        dataset_input_sha256=frozen["input_sha256"], dataset_gold_sha256=frozen["gold_sha256"],
        dataset_manifest_sha256=manifest_checksum,
        dataset_version=frozen["manifest"]["dataset_version"],
    )

    # Gold remains evaluator-only: only this scorer receives the verified gold map.
    gold = frozen["gold"]
    summary = summarize(trials, gold)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    trial_path = args.output_dir / f"{args.run_id}-trials.jsonl"
    with trial_path.open("w", encoding="utf-8", newline="\n") as stream:
        for trial in trials:
            stream.write(json.dumps(trial.model_dump(mode="json"), sort_keys=True, ensure_ascii=False) + "\n")
    evaluator_path = args.output_dir / f"{args.run_id}-evaluation.json"
    evaluator_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    run_metadata = {
        "run_id": args.run_id,
        "started_at_utc": started_at,
        "dataset_version": frozen["manifest"]["dataset_version"],
        "input_sha256": frozen["input_sha256"],
        "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": manifest_checksum,
        "model_config_hash": stable_hash(raw_config),
        "configuration_version": "model-config.v1",
        "schema_version": "research-output.v2",
        "evaluator_version": "evaluator.v2",
        "policy_version": "dry-run-policy.v2",
        "adapter_protocol_version": "adapter.v1",
        "prompt_hashes": {key: hashlib.sha256(value.encode("utf-8")).hexdigest()
                          for key, value in PROMPTS.items()},
        "replicates": args.replicates,
        "condition_order_seed": args.order_seed,
        "conditions": [condition.value for condition in Condition],
        "trial_count": len(trials),
        "trial_artifact": trial_path.name,
        "evaluator_artifact": evaluator_path.name,
        "adapter": "MockAdapter",
        "adapter_version": MockAdapter.adapter_version,
        "prompt_versions": PROMPT_VERSIONS,
    }
    run_metadata["run_fingerprint"] = stable_hash({
        "dataset_version": run_metadata["dataset_version"],
        "input_sha256": frozen["input_sha256"], "gold_sha256": frozen["gold_sha256"],
        "manifest_sha256": manifest_checksum, "model_config_hash": run_metadata["model_config_hash"],
        "prompt_hashes": run_metadata["prompt_hashes"], "schema_version": run_metadata["schema_version"],
        "prompt_versions": run_metadata["prompt_versions"],
        "evaluator_version": run_metadata["evaluator_version"], "policy_version": run_metadata["policy_version"],
        "adapter_protocol_version": run_metadata["adapter_protocol_version"],
        "configuration_version": run_metadata["configuration_version"],
        "adapter": run_metadata["adapter"], "adapter_version": run_metadata["adapter_version"],
        "conditions": run_metadata["conditions"],
        "replicates": run_metadata["replicates"], "condition_order_seed": run_metadata["condition_order_seed"],
    })
    metadata_path = args.output_dir / f"{args.run_id}-run.json"
    metadata_path.write_text(json.dumps(run_metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"trial_artifact": str(trial_path), "evaluation_artifact": str(evaluator_path), "run_artifact": str(metadata_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
