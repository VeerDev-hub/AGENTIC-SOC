"""Fail-closed verification for the frozen synthetic datasets (v1, v2)."""

import hashlib
import json
from collections import Counter
from pathlib import Path

from ..schema import GoldCase, ModelInputCase


DATASET_VERSION = "agenticsoc-synthetic-v1"
# Pinned at review time. A frozen-content change requires a new dataset version
# and an explicit update to these reviewed checksums.
PINNED_SHA256 = {
    "inputs.jsonl": "ff7cfc857fa6b610075c09509dd0d4082232871e773639a0019eb7b245d6982f",
    "gold.jsonl": "911cdfa1fffe7294054c956d6516a9491a7edaee16330d94c44192932fb20ee1",
}
DATASET_VERSION_V2 = "agenticsoc-synthetic-v2"
PINNED_SHA256_BY_VERSION = {
    DATASET_VERSION: PINNED_SHA256,
    DATASET_VERSION_V2: {
        "inputs.jsonl": "7801b880a529e65c2e23fb357a2a8be113bb1c1d2b727c53e4bf5dd5b1a60dd0",
        "gold.jsonl": "a51a0bc48f72e29a06c3492ed5011a7269956b200d129cf7c0b09cce7d92f2e1",
        "attack_meta.jsonl": "02128b6190ce21f30b9f3f71981c7f565f0397dcc2a223a224023b93445d44e1",
    },
}


class DatasetIntegrityError(ValueError):
    pass


def _jsonl(path):
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DatasetIntegrityError(f"Cannot read valid JSONL {path.name}: {exc}") from exc


def _unique(rows, name):
    ids = [row.get("case_id") for row in rows]
    if any(not isinstance(item, str) or not item.strip() for item in ids):
        raise DatasetIntegrityError(f"{name} contains a blank or invalid case_id")
    if len(ids) != len(set(ids)):
        raise DatasetIntegrityError(f"{name} contains duplicate case IDs")
    return set(ids)


def validate_record_sets(inputs, gold, manifest):
    """Validate in-memory records too; this never repairs or regenerates data."""
    if manifest.get("dataset_version") not in PINNED_SHA256_BY_VERSION:
        raise DatasetIntegrityError("Unsupported dataset version")
    if len(inputs) != manifest.get("case_count") or len(gold) != manifest.get("case_count"):
        raise DatasetIntegrityError("Dataset record count does not match manifest")
    input_ids, gold_ids = _unique(inputs, "inputs"), _unique(gold, "gold")
    if input_ids != gold_ids:
        raise DatasetIntegrityError("Input/gold case IDs do not match exactly")
    try:
        # These rows were decoded from JSON. Pydantic's strict JSON validation
        # accepts enum wire values while retaining strict Python-object checks.
        typed_inputs = [ModelInputCase.model_validate_json(json.dumps(row, ensure_ascii=False)) for row in inputs]
        typed_gold = [GoldCase.model_validate_json(json.dumps(row, ensure_ascii=False)) for row in gold]
    except Exception as exc:
        raise DatasetIntegrityError(f"Dataset schema validation failed: {exc}") from exc
    input_by_id = {row.case_id: row for row in typed_inputs}
    for label in typed_gold:
        case = input_by_id[label.case_id]
        for fragment in label.fragments:
            event = next((event for event in case.events if event.event_id == fragment.event_id), None)
            if event is None or fragment.field_path not in event.fields:
                raise DatasetIntegrityError(f"Invalid fragment reference in {label.case_id}")
    counts = dict(sorted(Counter(row.scenario.value for row in typed_gold).items()))
    if counts != manifest.get("scenario_counts"):
        raise DatasetIntegrityError("Scenario counts do not match manifest")
    fragments = Counter(str(row.fragment_count_k) for row in typed_gold if row.fragment_count_k is not None)
    if dict(sorted(fragments.items())) != manifest.get("fragmentation_counts"):
        raise DatasetIntegrityError("Fragmentation counts do not match manifest")
    return typed_inputs, {row.case_id: row for row in typed_gold}


def verify_dataset(dataset_dir: Path):
    """Verify manifest, pinned file digests, counts, IDs, schemas and lineage."""
    try:
        manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DatasetIntegrityError(f"Cannot read manifest: {exc}") from exc
    pinned = PINNED_SHA256_BY_VERSION.get(manifest.get("dataset_version"))
    if pinned is None:
        raise DatasetIntegrityError("Unsupported dataset version")
    inputs, gold = [], []
    observed = {}
    for name in pinned:
        try:
            raw = (dataset_dir / name).read_bytes()
        except OSError as exc:
            raise DatasetIntegrityError(f"Missing dataset file {name}") from exc
        observed[name] = hashlib.sha256(raw).hexdigest()
        if manifest.get("sha256", {}).get(name) != observed[name]:
            raise DatasetIntegrityError(f"Manifest checksum mismatch for {name}")
        if pinned[name] != observed[name]:
            raise DatasetIntegrityError(f"Frozen checksum changed for {name}; create a versioned dataset")
        rows = _jsonl(dataset_dir / name)
        if name == "inputs.jsonl":
            inputs = rows
        elif name == "gold.jsonl":
            gold = rows
    typed_inputs, typed_gold = validate_record_sets(inputs, gold, manifest)
    return {
        "inputs": typed_inputs,
        "gold": typed_gold,
        "manifest": manifest,
        "input_sha256": observed["inputs.jsonl"],
        "gold_sha256": observed["gold.jsonl"],
    }
