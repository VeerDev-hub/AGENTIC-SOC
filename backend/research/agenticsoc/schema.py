"""Strict model-visible, evaluator-only, and trial-record schemas."""

import json
import math
import re
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from apps.agentic.analysis.provenance import EvidenceField, FieldProvenance


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def validate_text_id(value: str, *, field: str, maximum: int) -> str:
    if not value or value != value.strip() or len(value) > maximum or _CONTROL.search(value):
        raise ValueError(f"{field} is blank, padded, too long, or contains control characters")
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} contains unsupported identifier characters")
    return value


class Event(StrictModel):
    event_id: str = Field(min_length=1, max_length=255)
    timestamp: str = Field(min_length=1, max_length=64)
    source_type: str = Field(min_length=1, max_length=80)
    fields: dict[str, Any]

    @field_validator("event_id")
    @classmethod
    def event_id_is_safe(cls, value):
        return validate_text_id(value, field="event_id", maximum=255)

    @field_validator("source_type")
    @classmethod
    def source_type_is_safe(cls, value):
        return validate_text_id(value, field="source_type", maximum=80)

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_safe(cls, value):
        if not value.strip() or len(value) > 64 or _CONTROL.search(value):
            raise ValueError("timestamp must be nonblank and contain no control characters")
        return value

    @field_validator("fields")
    @classmethod
    def field_paths_and_values_are_safe_json(cls, fields):
        def check(item):
            if item is None or type(item) in (str, bool, int):
                return
            if type(item) is float:
                if not math.isfinite(item):
                    raise ValueError("event values must not contain non-finite numbers")
                return
            if isinstance(item, list):
                for child in item:
                    check(child)
                return
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise ValueError("event object keys must be strings")
                for child in item.values():
                    check(child)
                return
            raise ValueError("event values must be JSON-compatible")

        for path in fields:
            if not path or path != path.strip() or len(path) > 1024 or _CONTROL.search(path):
                raise ValueError("field paths must be nonblank, bounded, and control-free")
        check(fields)
        if not fields:
            raise ValueError("events must contain at least one evidence field")
        json.dumps(fields, ensure_ascii=False, allow_nan=False)
        return fields


class ModelInputCase(StrictModel):
    """Raw input data. This type has no fields for evaluator labels."""

    case_id: str = Field(pattern=r"^case-[0-9]{4}$")
    task: str = Field(min_length=1, max_length=2000)
    events: list[Event] = Field(min_length=1)

    @model_validator(mode="after")
    def event_ids_unique(self):
        ids = [event.event_id for event in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("event_id values must be unique within a case")
        return self


class Scenario(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    DIRECT_INJECTION = "direct_injection"
    FRAGMENTED_INJECTION = "fragmented_injection"
    BENIGN_SUSPICIOUS = "benign_suspicious"
    PROHIBITED_ACTION = "prohibited_action"


class FragmentReference(StrictModel):
    event_id: str = Field(min_length=1, max_length=255)
    field_path: str = Field(min_length=1, max_length=1024)
    piece_index: str = Field(pattern=r"^[1-9][0-9]*$")

    @field_validator("event_id")
    @classmethod
    def safe_event_id(cls, value):
        return validate_text_id(value, field="event_id", maximum=255)

    @field_validator("field_path")
    @classmethod
    def safe_field_path(cls, value):
        if value != value.strip() or _CONTROL.search(value):
            raise ValueError("field_path must be unpadded and control-free")
        return value


class GoldCase(StrictModel):
    """Evaluator-only labels. It is never accepted by a model adapter."""

    case_id: str = Field(pattern=r"^case-[0-9]{4}$")
    scenario: Scenario
    malicious: bool
    injection_present: bool
    attack_objective: str | None = None
    attack_success_criterion: Literal["benign_verdict", "prohibited_action_proposal"] | None = None
    fragments: list[FragmentReference] = Field(default_factory=list)
    fragment_count_k: int | None = Field(default=None, ge=1)
    expected_verdict: Literal["benign", "malicious", "uncertain"]
    material_disagreements: list[dict[str, str]] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    benign_suspicious: bool = False

    @model_validator(mode="after")
    def labels_match_scenario_shape(self):
        if self.scenario is Scenario.FRAGMENTED_INJECTION:
            if not self.injection_present or self.fragment_count_k != len(self.fragments):
                raise ValueError("fragmented injection requires matching K and fragment references")
            indexes = sorted(int(item.piece_index) for item in self.fragments)
            if indexes != list(range(1, self.fragment_count_k + 1)):
                raise ValueError("fragment indexes must be unique and contiguous")
        elif self.fragment_count_k is not None or self.fragments:
            raise ValueError("fragment metadata is reserved for fragmented injection cases")
        if self.scenario is Scenario.PROHIBITED_ACTION:
            if not self.prohibited_actions or self.attack_success_criterion != "prohibited_action_proposal":
                raise ValueError("prohibited-action gold requires an action and matching success criterion")
        if self.injection_present != (self.attack_success_criterion is not None):
            raise ValueError("injection label and operational success criterion must agree")
        return self


class Verdict(str, Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNCERTAIN = "uncertain"


class ModelField(StrictModel):
    field_path: str = Field(min_length=1, max_length=1024)
    value: Any
    provenance: FieldProvenance | None = None

    @field_validator("field_path")
    @classmethod
    def safe_path(cls, value):
        if value != value.strip() or _CONTROL.search(value):
            raise ValueError("field_path must be unpadded and control-free")
        return value


class ModelEvent(StrictModel):
    event_id: str = Field(min_length=1, max_length=255)
    timestamp: str
    source_type: str
    fields: list[ModelField] = Field(min_length=1)

    @field_validator("event_id")
    @classmethod
    def safe_event_id(cls, value):
        return validate_text_id(value, field="event_id", maximum=255)

    @field_validator("source_type")
    @classmethod
    def safe_source_type(cls, value):
        return validate_text_id(value, field="source_type", maximum=80)

    @field_validator("timestamp")
    @classmethod
    def safe_timestamp(cls, value):
        if not value.strip() or len(value) > 64 or _CONTROL.search(value):
            raise ValueError("timestamp must be nonblank, bounded, and control-free")
        return value

    @model_validator(mode="after")
    def unique_paths(self):
        paths = [item.field_path for item in self.fields]
        if len(paths) != len(set(paths)):
            raise ValueError("field paths must be unique within an event")
        return self


class ModelRequest(StrictModel):
    """The only adapter request: task plus one event/evidence representation."""

    task: str = Field(min_length=1, max_length=2000)
    events: list[ModelEvent] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_events(self):
        ids = [event.event_id for event in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("event IDs must be unique within a request")
        return self


class EvidenceReference(StrictModel):
    event_id: str = Field(min_length=1, max_length=255)
    field_path: str = Field(min_length=1, max_length=1024)

    @field_validator("event_id")
    @classmethod
    def safe_event_id(cls, value):
        return validate_text_id(value, field="event_id", maximum=255)

    @field_validator("field_path")
    @classmethod
    def safe_field_path(cls, value):
        if value != value.strip() or _CONTROL.search(value):
            raise ValueError("field_path must be unpadded and control-free")
        return value


class ActionProposal(StrictModel):
    action: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=255)
    rationale: str = Field(default="", max_length=2000)


class Assessment(StrictModel):
    assessor: str = Field(min_length=1, max_length=80)
    verdict: Verdict
    evidence_refs: list[EvidenceReference] = Field(default_factory=list)
    rationale: str = Field(default="", max_length=4000)

    @field_validator("evidence_refs")
    @classmethod
    def unique_references(cls, values):
        pairs = [(item.event_id, item.field_path) for item in values]
        if len(pairs) != len(set(pairs)):
            raise ValueError("duplicate evidence references are not allowed")
        return values


class ModelOutput(StrictModel):
    assessment: Assessment
    action_proposals: list[ActionProposal] = Field(default_factory=list)


class Condition(str, Enum):
    BASELINE_NONE = "Baseline-None"
    BASELINE_PROMPT = "Baseline-Prompt"
    PTA = "PTA"


class ModelConfig(StrictModel):
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    temperature: float | None = Field(default=None, ge=0, le=2)
    reasoning_effort: Literal["none", "low", "medium", "high", "xhigh", "max"] | None = None
    max_output_tokens: int = Field(ge=1)
    input_price_per_million: float | None = Field(default=None, ge=0)
    output_price_per_million: float | None = Field(default=None, ge=0)
    price_schedule_id: str | None = None
    price_currency: str | None = None
    simulated_capabilities: list[str]

    @field_validator("price_schedule_id")
    @classmethod
    def price_schedule_is_named(cls, value):
        if value is not None and (not value.strip() or len(value) > 128 or _CONTROL.search(value)):
            raise ValueError("price_schedule_id must be nonblank, bounded, and control-free")
        return value

    @field_validator("simulated_capabilities")
    @classmethod
    def capabilities_are_valid(cls, values):
        if any(not isinstance(value, str) or not value.strip() or len(value) > 100 or _CONTROL.search(value)
               for value in values):
            raise ValueError("simulated capabilities must be nonblank bounded strings")
        return values

    @model_validator(mode="after")
    def price_fields_are_complete(self):
        supplied = any(value is not None for value in (
            self.input_price_per_million, self.output_price_per_million,
            self.price_schedule_id, self.price_currency,
        ))
        if supplied and not all(value is not None for value in (
            self.input_price_per_million, self.output_price_per_million,
            self.price_schedule_id, self.price_currency,
        )):
            raise ValueError("a local price schedule requires both rates, its ID, and currency")
        if self.price_currency is not None and not re.fullmatch(r"[A-Z]{3}", self.price_currency):
            raise ValueError("price_currency must be an explicit ISO-style currency code")
        return self


class ModelCallRecord(StrictModel):
    stage: Literal["analysis", "validation"]
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["complete", "incomplete"]
    latency_ms: float = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    provider_cost: float | None = Field(default=None, ge=0)
    provider_currency: str | None = None
    estimated_cost: float | None = Field(default=None, ge=0)
    estimated_currency: str | None = None
    cost_basis: str | None = None
    request_attempts: int = Field(default=1, ge=0)
    returned_model: str | None = None
    execution_location: Literal["local", "remote", "mock"] | None = None
    runtime_name: str | None = None
    runtime_version: str | None = None
    provider_inference_charge: float | None = Field(default=None, ge=0)
    provider_inference_charge_basis: str | None = None
    runtime_total_duration_ms: float | None = Field(default=None, ge=0)
    runtime_load_duration_ms: float | None = Field(default=None, ge=0)
    failure_kind: Literal["timeout", "rate_limit", "refused", "malformed", "budget", "provider", "validation"] | None = None

    @field_validator("provider_currency")
    @classmethod
    def provider_currency_is_explicit(cls, value):
        if value is not None and not re.fullmatch(r"[A-Z]{3}", value):
            raise ValueError("provider_currency must be a three-letter uppercase code")
        return value

    @field_validator("estimated_currency")
    @classmethod
    def estimated_currency_is_explicit(cls, value):
        if value is not None and not re.fullmatch(r"[A-Z]{3}", value):
            raise ValueError("estimated_currency must be a three-letter uppercase code")
        return value


class DryRunAction(StrictModel):
    action: str
    target: str
    outcome: Literal["allow", "deny", "require_approval", "within_capability", "would_deny", "would_require_approval", "would_exceed_capability"]
    would_breach: bool
    executed: Literal[False] = False


class TrialRecord(StrictModel):
    run_id: str
    case_id: str
    condition: str
    replicate: int = Field(ge=0)
    config_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    input_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    dataset_input_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    dataset_gold_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    dataset_manifest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    dataset_version: str | None = None
    provider: str | None = None
    requested_model: str | None = None
    returned_models: list[str] = Field(default_factory=list)
    execution_location: Literal["local", "remote", "mock"] | None = None
    runtime_name: str | None = None
    runtime_version: str | None = None
    provider_inference_charge_total: float | None = Field(default=None, ge=0)
    provider_inference_charge_basis: str | None = None
    prompt_versions: dict[str, str] = Field(default_factory=dict)
    status: Literal["complete", "incomplete"]
    incomplete_reason: str | None = None
    model_calls: int = Field(ge=0)
    api_request_count: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    latency_ms: float = Field(ge=0)
    per_stage_latency_ms: dict[str, float] = Field(default_factory=dict)
    call_records: list[ModelCallRecord] = Field(default_factory=list)
    cost_amount: float | None = Field(default=None, ge=0)
    cost_currency: str | None = None
    cost_basis: str
    cost_complete: bool
    attempted_breach_actions: int = Field(default=0, ge=0)
    approved_breach_actions: int = Field(default=0, ge=0)
    executed_breach_actions: int = Field(default=0, ge=0)
    primary_assessment: ModelOutput | None = None
    validation_assessment: ModelOutput | None = None
    final_verdict: Verdict | None = None
    dissent_detected: bool = False
    assessment_provenance: list[EvidenceField] = Field(default_factory=list)
    dry_run_actions: list[DryRunAction] = Field(default_factory=list)

    @field_validator("cost_currency")
    @classmethod
    def trial_currency_is_explicit(cls, value):
        if value is not None and not re.fullmatch(r"[A-Z]{3}", value):
            raise ValueError("cost_currency must be a three-letter uppercase code")
        return value
