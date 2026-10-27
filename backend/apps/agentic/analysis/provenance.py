"""Standalone provenance types and serialization for future PTA stage boundaries.

These models validate structure and lineage. They do not authenticate callers or
prove source authenticity; trusted source classification belongs in application
code outside untrusted payloads.
"""

import hashlib
import json
import re
from datetime import date, datetime
from enum import Enum
from typing import Any, Iterable, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ProvenanceLabel(str, Enum):
    T0 = "T0"
    T1 = "T1"
    T2 = "T2"


class ProvenanceSource(str, Enum):
    """Source kinds available to ordinary ingestion; T0 is deliberately absent."""

    PLATFORM_CONTEXT = "platform_context"
    ANALYST_CONTEXT = "analyst_context"
    EXTERNAL_EVENT = "external_event"


_SOURCE_LABELS = {
    ProvenanceSource.PLATFORM_CONTEXT: ProvenanceLabel.T1,
    ProvenanceSource.ANALYST_CONTEXT: ProvenanceLabel.T1,
    ProvenanceSource.EXTERNAL_EVENT: ProvenanceLabel.T2,
}
_LABEL_ORDER = {
    ProvenanceLabel.T0: 0,
    ProvenanceLabel.T1: 1,
    ProvenanceLabel.T2: 2,
}
_MESSAGE_TYPES = {
    "ingest": "evidence.ingested",
    "process": "evidence.processed",
    "validate": "validation.completed",
    "policy": "policy.decision",
}
_IDENTIFIER_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")


def _validate_identifier(value: str, *, field_name: str, max_length: int) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank.")
    if len(normalized) > max_length:
        raise ValueError(f"{field_name} exceeds {max_length} characters.")
    if not _IDENTIFIER_PATTERN.fullmatch(normalized):
        raise ValueError(f"{field_name} must not contain control characters.")
    return normalized


def _json_value(value: Any) -> Any:
    """Normalize supported Python values to JSON-native values for hashing/storage."""
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return _json_value(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("Provenance object keys must be strings.")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _canonical_json(value: Any) -> str:
    """Serialize with this module's deterministic Python JSON representation.

    This is stable for the supported values and Python settings below. It is not
    a cross-language canonical JSON standard and does not authenticate content.
    """
    try:
        return json.dumps(
            _json_value(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Provenance values must be JSON-serializable.") from exc


def content_hash(value: Any) -> str:
    """Return SHA-256 of UTF-8 deterministic Python JSON; this is not a signature."""
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


class SourceClassification(BaseModel):
    """Trusted-code classification separated from the evidence value itself.

    The source-kind enum contains only T1/T2 categories. An untrusted payload
    must never be allowed to select or construct this classification directly.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source_kind: ProvenanceSource

    @property
    def label(self) -> ProvenanceLabel:
        return _SOURCE_LABELS[self.source_kind]


def classify_source(source_kind: ProvenanceSource) -> SourceClassification:
    """Classify a source in trusted ingestion code; T0 is not assignable here."""
    if not isinstance(source_kind, ProvenanceSource):
        raise TypeError("source_kind must be classified by trusted code as ProvenanceSource.")
    return SourceClassification(source_kind=source_kind)


class SourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    source_id: str = Field(min_length=1, max_length=255)
    field_path: str = Field(min_length=1, max_length=1024)
    label: ProvenanceLabel
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("source_id", "field_path")
    @classmethod
    def validate_source_identifiers(cls, value, info):
        return _validate_identifier(value, field_name=info.field_name, max_length=1024)


class FieldProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    label: ProvenanceLabel
    sources: list[SourceReference] = Field(min_length=1)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    transformation_id: str | None = None

    @field_validator("sources")
    @classmethod
    def references_are_consistent_and_sorted(cls, sources):
        by_identity = {}
        for source in sources:
            identity = (source.source_id, source.field_path)
            existing = by_identity.get(identity)
            if existing is not None and existing != source:
                raise ValueError(
                    "Conflicting source references share the same source_id and field_path."
                )
            by_identity[identity] = source
        return sorted(
            by_identity.values(),
            key=lambda source: (
                source.source_id,
                source.field_path,
                source.label.value,
                source.content_hash,
            ),
        )

    @field_validator("transformation_id")
    @classmethod
    def validate_transformation_id(cls, value):
        if value is None:
            return value
        return _validate_identifier(value, field_name="transformation_id", max_length=255)

    @model_validator(mode="after")
    def label_must_equal_maximum_source_taint(self):
        highest_source_label = max(
            (source.label for source in self.sources),
            key=_LABEL_ORDER.__getitem__,
        )
        if self.label != highest_source_label:
            raise ValueError("Provenance label must equal the maximum source taint.")
        if self.transformation_id is None and len(self.sources) != 1:
            raise ValueError("Non-derived provenance must have exactly one source reference.")
        return self


class EvidenceField(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    field_path: str = Field(min_length=1, max_length=1024)
    value: Any
    provenance: FieldProvenance

    @field_validator("field_path")
    @classmethod
    def validate_field_path(cls, value):
        return _validate_identifier(value, field_name="field_path", max_length=1024)

    @field_validator("value", mode="before")
    @classmethod
    def normalize_value_to_json(cls, value):
        return _json_value(value)

    @model_validator(mode="after")
    def content_hash_must_match_value(self):
        expected_hash = content_hash(self.value)
        if self.provenance.content_hash != expected_hash:
            raise ValueError("Evidence content hash does not match its value.")
        if self.provenance.transformation_id is None:
            source = self.provenance.sources[0]
            if source.content_hash != expected_hash:
                raise ValueError("Source content hash does not match original evidence value.")
        return self


class StageName(str, Enum):
    INGEST = "ingest"
    PROCESS = "process"
    VALIDATE = "validate"
    POLICY = "policy"


class StageMessage(BaseModel):
    """Strict pta.v1 envelope; payload-specific schemas are not implemented yet."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["pta.v1"]
    message_id: str = Field(min_length=1, max_length=255)
    run_id: str = Field(min_length=1, max_length=255)
    stage: StageName
    message_type: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any]
    evidence: list[EvidenceField] = Field(default_factory=list)
    parent_message_ids: list[str] = Field(default_factory=list)

    @field_validator("message_id", "run_id", "message_type")
    @classmethod
    def validate_message_identifiers(cls, value, info):
        return _validate_identifier(value, field_name=info.field_name, max_length=255)

    @field_validator("parent_message_ids")
    @classmethod
    def validate_parent_message_ids(cls, values):
        normalized = [
            _validate_identifier(value, field_name="parent_message_id", max_length=255)
            for value in values
        ]
        if len(normalized) != len(set(normalized)):
            raise ValueError("Parent message IDs must be unique.")
        return normalized

    @field_validator("payload")
    @classmethod
    def validate_json_payload(cls, value):
        _canonical_json(value)
        return value

    @model_validator(mode="after")
    def validate_stage_message_type(self):
        expected_message_type = _MESSAGE_TYPES[self.stage.value]
        if self.message_type != expected_message_type:
            raise ValueError(
                f"Stage {self.stage.value!r} requires message_type {expected_message_type!r}."
            )
        if self.message_id in self.parent_message_ids:
            raise ValueError("A message cannot be its own parent.")
        return self


def assign_evidence(
    *,
    classification: SourceClassification,
    source_id: str,
    field_path: str,
    value: Any,
) -> EvidenceField:
    """Attach T1/T2 provenance using a separate trusted source classification.

    T0 is intentionally unavailable through this general-purpose helper.
    """
    if type(classification) is not SourceClassification:
        raise TypeError("classification must come from trusted source-classification code.")
    label = _SOURCE_LABELS[classification.source_kind]
    normalized_value = _json_value(value)
    value_hash = content_hash(normalized_value)
    source_reference = SourceReference(
        source_id=source_id,
        field_path=field_path,
        label=label,
        content_hash=value_hash,
    )
    return EvidenceField(
        field_path=field_path,
        value=normalized_value,
        provenance=FieldProvenance(
            label=label,
            sources=[source_reference],
            content_hash=value_hash,
        ),
    )


def derive_evidence(
    *,
    field_path: str,
    value: Any,
    parents: Iterable[EvidenceField],
    transformation_id: str,
) -> EvidenceField:
    """Create evidence with maximum parent taint and deterministic full lineage."""
    parent_fields = list(parents)
    if not parent_fields:
        raise ValueError("Derived evidence requires at least one attributable parent.")
    if any(not isinstance(parent, EvidenceField) for parent in parent_fields):
        raise TypeError("Every parent must be a validated EvidenceField.")
    if not isinstance(transformation_id, str):
        raise TypeError("transformation_id must be a string.")
    if not transformation_id.strip():
        raise ValueError("transformation_id must not be blank.")

    label = max(
        (parent.provenance.label for parent in parent_fields),
        key=_LABEL_ORDER.__getitem__,
    )
    all_sources = [
        source
        for parent in parent_fields
        for source in parent.provenance.sources
    ]
    normalized_value = _json_value(value)

    return EvidenceField(
        field_path=field_path,
        value=normalized_value,
        provenance=FieldProvenance(
            label=label,
            sources=all_sources,
            content_hash=content_hash(normalized_value),
            transformation_id=transformation_id,
        ),
    )


def _deserialize_model(model: type[BaseModel], payload: Any) -> Any:
    if isinstance(payload, (str, bytes, bytearray)):
        return model.model_validate_json(payload)
    return model.model_validate_json(_canonical_json(payload))


def serialize_evidence_field(evidence: EvidenceField) -> dict[str, Any]:
    """Return a JSON-compatible representation with field-level provenance."""
    return evidence.model_dump(mode="json")


def deserialize_evidence_field(payload: Any) -> EvidenceField:
    """Validate and deserialize a mapping or JSON text as an evidence field."""
    return _deserialize_model(EvidenceField, payload)


def serialize_stage_message(message: StageMessage) -> dict[str, Any]:
    return message.model_dump(mode="json")


def deserialize_stage_message(payload: Any) -> StageMessage:
    """Validate and deserialize a mapping or JSON text as a pta.v1 message."""
    return _deserialize_model(StageMessage, payload)
