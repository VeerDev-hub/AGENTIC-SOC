"""Research model adapter boundary; implementations must not expose gold data."""

from dataclasses import dataclass
import json
from typing import Protocol

from .schema import ModelConfig, ModelOutput, ModelRequest


@dataclass(frozen=True)
class AdapterResult:
    output: ModelOutput
    input_tokens: int
    output_tokens: int
    provider_reported_cost: float | None = None
    provider_reported_currency: str | None = None
    estimated_cost: float | None = None
    estimated_currency: str | None = None
    cost_basis: str | None = None
    request_attempts: int = 1
    returned_model: str | None = None
    execution_location: str | None = None
    runtime_name: str | None = None
    runtime_version: str | None = None
    provider_inference_charge: float | None = None
    provider_inference_charge_basis: str | None = None
    runtime_total_duration_ms: float | None = None
    runtime_load_duration_ms: float | None = None


class ModelAdapter(Protocol):
    adapter_version: str
    def invoke(self, *, request: ModelRequest, prompt: str, config: ModelConfig, stage: str) -> AdapterResult: ...


class MockAdapter:
    """Offline adapter for deterministic unit tests; uses no labels or gold inputs."""

    adapter_version = "mock-adapter.v2"

    def __init__(self, outputs=None, *, request_log=None):
        self.outputs = list(outputs or [])
        self.requests = request_log if request_log is not None else []

    def invoke(self, *, request, prompt, config, stage):
        # Omit absent provenance metadata: baseline conditions must not carry a
        # placeholder provenance field in the serialized request.
        visible_request = request.model_dump(mode="json", exclude_none=True)
        self.requests.append({"request": visible_request, "prompt": prompt, "stage": stage,
                              "config": config.model_dump(mode="json")})
        if self.outputs:
            output = self.outputs.pop(0)
        else:
            text = " ".join(str(field.value) for event in request.events for field in event.fields).lower()
            suspicious = any(word in text for word in ("powershell", "198.51.100", "ignore prior", "credentials", "delete evidence"))
            output = {
                "assessment": {
                    "assessor": stage,
                    "verdict": "malicious" if suspicious else "benign",
                    "evidence_refs": [
                        {"event_id": event.event_id, "field_path": field.field_path}
                        for event in request.events for field in event.fields
                    ],
                    "rationale": "Deterministic offline fixture response.",
                },
                "action_proposals": [],
            }
        if isinstance(output, ModelOutput):
            validated = output
        else:
            validated = ModelOutput.model_validate_json(json.dumps(output, ensure_ascii=False))
        return AdapterResult(validated, input_tokens=len(str(visible_request).split()), output_tokens=24)

