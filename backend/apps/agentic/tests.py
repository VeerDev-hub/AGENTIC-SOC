import json
from datetime import datetime, timezone
from itertools import product

from django.test import SimpleTestCase
from pydantic import ValidationError

from apps.agentic.analysis.provenance import (
    EvidenceField,
    FieldProvenance,
    ProvenanceLabel,
    ProvenanceSource,
    SourceClassification,
    SourceReference,
    StageMessage,
    StageName,
    assign_evidence,
    classify_source,
    content_hash,
    derive_evidence,
    deserialize_evidence_field,
    deserialize_stage_message,
    serialize_evidence_field,
    serialize_stage_message,
)


def make_evidence(label, *, source_id, field_path, value):
    value_hash = content_hash(value)
    reference = SourceReference(
        source_id=source_id,
        field_path=field_path,
        label=label,
        content_hash=value_hash,
    )
    return EvidenceField(
        field_path=field_path,
        value=value,
        provenance=FieldProvenance(
            label=label,
            sources=[reference],
            content_hash=value_hash,
        ),
    )


def evidence_for_label(label, *, source_id, field_path="message", value=None):
    if label == ProvenanceLabel.T0:
        return make_evidence(label, source_id=source_id, field_path=field_path, value=value or "control")
    source = {
        ProvenanceLabel.T1: ProvenanceSource.PLATFORM_CONTEXT,
        ProvenanceLabel.T2: ProvenanceSource.EXTERNAL_EVENT,
    }[label]
    return assign_evidence(
        classification=classify_source(source),
        source_id=source_id,
        field_path=field_path,
        value=value if value is not None else source_id,
    )


def make_stage_message(**overrides):
    payload = {
        "schema_version": "pta.v1",
        "message_id": "msg-1",
        "run_id": "run-1",
        "stage": StageName.PROCESS,
        "message_type": "evidence.processed",
        "payload": {"findings": []},
        "evidence": [],
        "parent_message_ids": [],
    }
    payload.update(overrides)
    return StageMessage(**payload)


class ProvenanceAssignmentTests(SimpleTestCase):
    def test_source_classification_maps_only_non_control_sources(self):
        self.assertEqual(
            classify_source(ProvenanceSource.PLATFORM_CONTEXT).label,
            ProvenanceLabel.T1,
        )
        self.assertEqual(
            classify_source(ProvenanceSource.ANALYST_CONTEXT).label,
            ProvenanceLabel.T1,
        )
        self.assertEqual(
            classify_source(ProvenanceSource.EXTERNAL_EVENT).label,
            ProvenanceLabel.T2,
        )
        with self.assertRaises(ValueError):
            ProvenanceSource("trusted_control")

    def test_general_assignment_requires_separate_classification(self):
        with self.assertRaises(TypeError):
            assign_evidence(
                classification="trusted_control",
                source_id="event-1",
                field_path="message",
                value="untrusted",
            )
        with self.assertRaises(TypeError):
            classify_source("external_event")
        with self.assertRaises(ValidationError):
            SourceClassification.model_validate({"source_kind": "platform_context"})

    def test_assign_evidence_preserves_identity_path_value_and_hash(self):
        evidence = assign_evidence(
            classification=classify_source(ProvenanceSource.EXTERNAL_EVENT),
            source_id="event-42",
            field_path="message",
            value="investigate this event",
        )

        self.assertEqual(evidence.provenance.label, ProvenanceLabel.T2)
        source = evidence.provenance.sources[0]
        self.assertEqual(source.source_id, "event-42")
        self.assertEqual(source.field_path, "message")
        self.assertEqual(source.content_hash, content_hash("investigate this event"))
        self.assertEqual(evidence.provenance.content_hash, content_hash(evidence.value))


class ProvenancePropagationTests(SimpleTestCase):
    def test_every_parent_label_pair_propagates_the_maximum(self):
        labels = list(ProvenanceLabel)
        for left_label, right_label in product(labels, repeat=2):
            with self.subTest(left=left_label, right=right_label):
                left = evidence_for_label(left_label, source_id="left")
                right = evidence_for_label(right_label, source_id="right")

                derived = derive_evidence(
                    field_path="summary",
                    value="derived value",
                    parents=[left, right],
                    transformation_id="summarize.v1",
                )

                expected = max(
                    (left_label, right_label),
                    key={ProvenanceLabel.T0: 0, ProvenanceLabel.T1: 1, ProvenanceLabel.T2: 2}.__getitem__,
                )
                self.assertEqual(derived.provenance.label, expected)

    def test_multistep_derivation_preserves_all_sources_and_maximum_taint(self):
        first = evidence_for_label(ProvenanceLabel.T1, source_id="case-1", field_path="title")
        second = evidence_for_label(ProvenanceLabel.T2, source_id="event-2", field_path="message")
        intermediate = derive_evidence(
            field_path="finding",
            value="intermediate",
            parents=[first],
            transformation_id="extract.v1",
        )
        final = derive_evidence(
            field_path="summary",
            value="final",
            parents=[intermediate, second],
            transformation_id="summarize.v1",
        )

        self.assertEqual(final.provenance.label, ProvenanceLabel.T2)
        self.assertEqual(
            {(ref.source_id, ref.field_path) for ref in final.provenance.sources},
            {("case-1", "title"), ("event-2", "message")},
        )

    def test_exact_duplicate_references_are_deduplicated(self):
        parent = evidence_for_label(ProvenanceLabel.T2, source_id="event-1")
        derived = derive_evidence(
            field_path="summary",
            value="derived",
            parents=[parent, parent],
            transformation_id="merge.v1",
        )
        self.assertEqual(len(derived.provenance.sources), 1)

    def test_conflicting_hashes_for_same_source_identity_are_rejected(self):
        first = evidence_for_label(ProvenanceLabel.T2, source_id="event-1", value="one")
        second = evidence_for_label(ProvenanceLabel.T2, source_id="event-1", value="two")

        with self.assertRaisesMessage(ValidationError, "Conflicting source references"):
            derive_evidence(
                field_path="summary",
                value="derived",
                parents=[first, second],
                transformation_id="merge.v1",
            )

    def test_conflicting_labels_for_same_source_identity_are_rejected(self):
        first = make_evidence(
            ProvenanceLabel.T1,
            source_id="record-1",
            field_path="message",
            value="same",
        )
        second = make_evidence(
            ProvenanceLabel.T2,
            source_id="record-1",
            field_path="message",
            value="same",
        )

        with self.assertRaisesMessage(ValidationError, "Conflicting source references"):
            derive_evidence(
                field_path="summary",
                value="derived",
                parents=[first, second],
                transformation_id="merge.v1",
            )

    def test_lineage_order_is_deterministic_regardless_of_parent_order(self):
        first = evidence_for_label(ProvenanceLabel.T2, source_id="z-event")
        second = evidence_for_label(ProvenanceLabel.T1, source_id="a-case")
        from_forward = derive_evidence(
            field_path="summary",
            value="same result",
            parents=[first, second],
            transformation_id="merge.v1",
        )
        from_reverse = derive_evidence(
            field_path="summary",
            value="same result",
            parents=[second, first],
            transformation_id="merge.v1",
        )
        self.assertEqual(from_forward.provenance.sources, from_reverse.provenance.sources)
        self.assertEqual(
            serialize_evidence_field(from_forward),
            serialize_evidence_field(from_reverse),
        )
        self.assertEqual(
            [source.source_id for source in from_forward.provenance.sources],
            ["a-case", "z-event"],
        )

    def test_derivation_rejects_missing_or_unvalidated_parents(self):
        with self.assertRaisesMessage(ValueError, "requires at least one attributable parent"):
            derive_evidence(field_path="summary", value="orphan", parents=[], transformation_id="derive.v1")
        with self.assertRaisesMessage(TypeError, "validated EvidenceField"):
            derive_evidence(field_path="summary", value="bad", parents=[{}], transformation_id="derive.v1")


class ProvenanceSerializationTests(SimpleTestCase):
    def test_python_json_hash_test_vectors(self):
        self.assertEqual(
            content_hash(None),
            "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
        )
        self.assertEqual(
            content_hash({"a": 1, "b": "x"}),
            "ecf9e98ec0641e23113ff3ce8bdc78d0ddd249886517fd4a7f68cc83d4e65667",
        )

    def test_hash_is_stable_for_mapping_order_and_datetime_normalizes_to_json(self):
        self.assertEqual(content_hash({"a": 1, "b": 2}), content_hash({"b": 2, "a": 1}))
        timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(content_hash(timestamp), content_hash("2026-01-02T00:00:00+00:00"))

    def test_evidence_round_trips_through_json_text(self):
        evidence = assign_evidence(
            classification=classify_source(ProvenanceSource.ANALYST_CONTEXT),
            source_id="comment-7",
            field_path="body",
            value={"text": "analyst note", "created": datetime(2026, 1, 2, tzinfo=timezone.utc)},
        )
        serialized_text = json.dumps(serialize_evidence_field(evidence), ensure_ascii=False)
        restored = deserialize_evidence_field(serialized_text)

        self.assertEqual(restored, evidence)
        self.assertEqual(restored.value["created"], "2026-01-02T00:00:00+00:00")

    def test_stage_message_round_trips_through_json_text(self):
        evidence = evidence_for_label(ProvenanceLabel.T2, source_id="event-3")
        message = make_stage_message(evidence=[evidence])
        serialized_text = json.dumps(serialize_stage_message(message), ensure_ascii=False)

        self.assertEqual(deserialize_stage_message(serialized_text), message)


class StrictValidationTests(SimpleTestCase):
    def test_rejects_unsupported_message_version(self):
        with self.assertRaises(ValidationError):
            make_stage_message(schema_version="pta.v2")

    def test_rejects_blank_message_and_source_identifiers(self):
        with self.assertRaises(ValidationError):
            make_stage_message(message_id="  ")
        with self.assertRaises(ValidationError):
            make_stage_message(run_id="\n")
        with self.assertRaises(ValidationError):
            assign_evidence(
                classification=classify_source(ProvenanceSource.EXTERNAL_EVENT),
                source_id=" ",
                field_path="message",
                value="text",
            )

    def test_rejects_coercion_extra_fields_and_wrong_stage_message_type(self):
        with self.assertRaises(ValidationError):
            make_stage_message(message_id=42)
        with self.assertRaises(ValidationError):
            StageMessage.model_validate_json(
                json.dumps({**serialize_stage_message(make_stage_message()), "unexpected": True})
            )
        with self.assertRaises(ValidationError):
            make_stage_message(message_type="policy.decision")

    def test_rejects_invalid_source_references_and_hash_mismatch(self):
        with self.assertRaises(ValidationError):
            SourceReference(
                source_id="event-1",
                field_path="message",
                label=ProvenanceLabel.T2,
                content_hash="not-a-sha256",
            )
        with self.assertRaises(ValidationError):
            SourceReference(
                source_id="event-1",
                field_path="message",
                label="T3",
                content_hash=content_hash("text"),
            )
        valid = serialize_evidence_field(evidence_for_label(ProvenanceLabel.T2, source_id="event-1"))
        valid["provenance"]["sources"][0]["source_id"] = "\n"
        with self.assertRaises(ValidationError):
            deserialize_evidence_field(valid)

    def test_rejects_invalid_payload_shapes_and_non_json_values(self):
        with self.assertRaises(ValidationError):
            make_stage_message(payload=[])
        with self.assertRaises(ValidationError):
            make_stage_message(payload={"not_json": object()})
        with self.assertRaises(ValidationError):
            make_stage_message(parent_message_ids=["msg-1", "msg-1"])

    def test_rejects_lower_than_maximum_taint(self):
        t2 = evidence_for_label(ProvenanceLabel.T2, source_id="event-1")
        with self.assertRaises(ValidationError):
            FieldProvenance(
                label=ProvenanceLabel.T1,
                sources=t2.provenance.sources,
                content_hash=content_hash("different derived value"),
                transformation_id="derive.v1",
            )
