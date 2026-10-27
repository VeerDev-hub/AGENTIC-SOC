"""Isolated paired runner with explicit request, validation and accounting boundaries."""

import hashlib
import json
import random
import re
import time

from apps.agentic.analysis.provenance import ProvenanceSource, assign_evidence, classify_source, derive_evidence

from .actions import simulate
from .prompts import PROMPTS, PROMPT_VERSIONS
from .schema import (
    Assessment, Condition, DryRunAction, EvidenceReference, ModelCallRecord,
    ModelConfig, ModelEvent, ModelField, ModelInputCase, ModelOutput,
    ModelRequest, TrialRecord, Verdict,
)

SCHEMA_VERSION = "research-output.v2"
EVALUATOR_VERSION = "evaluator.v2"
POLICY_VERSION = "dry-run-policy.v2"
ADAPTER_PROTOCOL_VERSION = "adapter.v1"


def stable_hash(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _token_total(calls, field):
    attempted = [call for call in calls if call.request_attempts > 0]
    if not attempted:
        return 0
    values = [getattr(call, field) for call in attempted]
    return sum(values) if all(value is not None for value in values) else None


def model_input(case):
    return ModelInputCase.model_validate(case)


def _pta_fields(case):
    classification = classify_source(ProvenanceSource.EXTERNAL_EVENT)
    return {
        (event.event_id, path): assign_evidence(
            classification=classification, source_id=event.event_id,
            field_path=path, value=value,
        )
        for event in case.events
        for path, value in sorted(event.fields.items())
    }


def _request(case, *, pta_fields=None):
    events = []
    for event in case.events:
        fields = []
        for path, value in sorted(event.fields.items()):
            item = {"field_path": path, "value": value}
            if pta_fields is not None:
                # Pass the validated typed model; dumping to a Python dict would
                # turn enums into strings that strict Python validation rejects.
                item["provenance"] = pta_fields[(event.event_id, path)].provenance
            fields.append(ModelField.model_validate(item))
        events.append(ModelEvent(
            event_id=event.event_id, timestamp=event.timestamp,
            source_type=event.source_type, fields=fields,
        ))
    return ModelRequest(task=case.task, events=events)


def _validate_refs(output, request):
    supplied = {
        (event.event_id, item.field_path)
        for event in request.events for item in event.fields
    }
    reference = output.assessment.evidence_refs
    unknown = {(item.event_id, item.field_path) for item in reference} - supplied
    if unknown:
        raise ValueError(f"Model output references evidence not supplied to its stage: {sorted(unknown)}")


class StageValidationError(ValueError):
    failure_kind = "validation"


def final_decision(primary, validation=None):
    """Shared rule: one assessment decides; PTA disagreement maps to uncertain."""
    if validation is None:
        return primary.assessment.verdict
    if primary.assessment.verdict == validation.assessment.verdict:
        return primary.assessment.verdict
    return Verdict.UNCERTAIN


def _failed_record(*, run_id, case_id, condition, replicate, reason, started, config_hash=None,
                   input_hash=None, versions=None, calls=None, input_tokens=0, output_tokens=0,
                   costs_complete=False, cost_currency=None, dataset_input_sha256=None,
                   dataset_gold_sha256=None, dataset_manifest_sha256=None, dataset_version=None,
                   model_config=None, adapter=None):
    calls = calls or []
    stage_latencies = {}
    for call in calls:
        stage_latencies[call.stage] = stage_latencies.get(call.stage, 0.0) + call.latency_ms
    cost_pairs = [
        (call.provider_cost, call.provider_currency) if call.provider_cost is not None
        else (call.estimated_cost, call.estimated_currency)
        for call in calls if call.request_attempts > 0
    ]
    currencies = {currency for amount, currency in cost_pairs if amount is not None and currency is not None}
    known_amount = sum(amount for amount, currency in cost_pairs if amount is not None and currency is not None)
    cost_complete = (len(cost_pairs) == sum(1 for call in calls if call.request_attempts > 0)
                     and all(amount is not None and currency is not None for amount, currency in cost_pairs)
                     and len(currencies) == 1)
    return TrialRecord(
        run_id=str(run_id), case_id=str(case_id), condition=str(condition), replicate=max(0, int(replicate or 0)),
        config_hash=config_hash, input_hash=input_hash, dataset_input_sha256=dataset_input_sha256,
        dataset_gold_sha256=dataset_gold_sha256, dataset_manifest_sha256=dataset_manifest_sha256,
        dataset_version=dataset_version, prompt_versions=versions or {}, status="incomplete",
        provider=model_config.provider if model_config else None,
        requested_model=model_config.model if model_config else None,
        returned_models=sorted({c.returned_model for c in calls if c.returned_model}),
        execution_location=getattr(adapter, "execution_location", None),
        runtime_name=getattr(adapter, "runtime_name", None),
        runtime_version=getattr(adapter, "runtime_version", None),
        provider_inference_charge_total=(0.0 if getattr(adapter, "local_execution_confirmed", False) else None),
        provider_inference_charge_basis=(getattr(adapter, "inference_charge_basis", None)
                                         if getattr(adapter, "local_execution_confirmed", False) else None),
        incomplete_reason=reason[:2000], model_calls=len(calls),
        api_request_count=sum(c.request_attempts for c in calls),
        input_tokens=_token_total(calls, "input_tokens"),
        output_tokens=_token_total(calls, "output_tokens"),
        latency_ms=max(0.0, (time.perf_counter() - started) * 1000),
        per_stage_latency_ms=stage_latencies, call_records=calls,
        cost_amount=known_amount if cost_pairs else None,
        cost_currency=next(iter(currencies)) if len(currencies) == 1 else cost_currency,
        cost_basis="partial per-call cost; one or more API attempts have unavailable cost" if not cost_complete
                   else "per-call costs retained for incomplete trial",
        cost_complete=cost_complete,
    )


def run_trial(*, case_data, condition, replicate, run_id, config, adapter,
              dataset_input_sha256=None, dataset_gold_sha256=None,
              dataset_manifest_sha256=None, dataset_version="agenticsoc-synthetic-v1"):
    started = time.perf_counter()
    calls = []
    case_id = case_data.get("case_id", "unknown") if isinstance(case_data, dict) else "unknown"
    condition_value = getattr(condition, "value", str(condition))
    versions = {}
    config_hash = input_hash = None
    model_config = None
    try:
        condition = Condition(condition)
        condition_value = condition.value
        case = model_input(case_data)
        case_id = case.case_id
        config = config if isinstance(config, ModelConfig) else ModelConfig.model_validate(config)
        model_config = config
        versions = {condition.value: PROMPT_VERSIONS[condition.value]}
        if condition is Condition.PTA:
            versions["validator"] = PROMPT_VERSIONS["PTA-validator"]
        prompt_hashes = {key: _sha_text(PROMPTS[key]) for key in versions if key in PROMPTS}
        fingerprint_components = {
            "model_config": config.model_dump(mode="json"), "condition": condition.value,
            "prompts": prompt_hashes, "prompt_versions": versions,
            "adapter_protocol": ADAPTER_PROTOCOL_VERSION,
            "adapter": getattr(adapter, "adapter_version", type(adapter).__name__),
            "schema": SCHEMA_VERSION, "evaluator": EVALUATOR_VERSION,
            "policy": POLICY_VERSION,
            "dataset_version": dataset_version, "dataset_input_sha256": dataset_input_sha256,
            "dataset_gold_sha256": dataset_gold_sha256,
            "dataset_manifest_sha256": dataset_manifest_sha256,
        }
        runtime_fingerprint = getattr(adapter, "configuration_fingerprint", None)
        if runtime_fingerprint is not None:
            fingerprint_components["runtime_fingerprint"] = runtime_fingerprint
        config_hash = stable_hash(fingerprint_components)
        input_hash = stable_hash(case.model_dump(mode="json"))
    except Exception as exc:
        return _failed_record(run_id=run_id, case_id=case_id, condition=condition_value,
                              replicate=replicate, reason=f"input/configuration error: {type(exc).__name__}: {exc}",
                              started=started, config_hash=config_hash, input_hash=input_hash,
                              versions=versions, dataset_input_sha256=dataset_input_sha256,
                              dataset_gold_sha256=dataset_gold_sha256,
                              dataset_manifest_sha256=dataset_manifest_sha256,
                              dataset_version=dataset_version, model_config=model_config, adapter=adapter)

    stage_latencies = {}
    primary = validation = None
    dry_actions = []
    derived_evidence = []
    try:
        evidence = _pta_fields(case) if condition is Condition.PTA else None
        primary_request = _request(case, pta_fields=evidence)
        analysis_started = time.perf_counter()
        primary = _invoke(adapter, primary_request, PROMPTS[condition.value], config, "analysis", calls)
        _validate_refs(primary, primary_request)
        if evidence is not None:
            derived_evidence.append(derive_evidence(
                field_path="primary_assessment", value=primary.model_dump(mode="json"),
                parents=evidence.values(), transformation_id="agenticsoc.assessment.v1",
            ))
        stage_latencies["analysis"] = (time.perf_counter() - analysis_started) * 1000

        if condition is Condition.PTA:
            # Validator gets the same original case representation, never the primary assessment.
            # Its own result is recorded independently and compared only after it returns.
            validation_request = _request(case, pta_fields=evidence)
            validation_started = time.perf_counter()
            validation = _invoke(adapter, validation_request, PROMPTS["PTA-validator"], config, "validation", calls)
            _validate_refs(validation, validation_request)
            derived_evidence.append(derive_evidence(
                field_path="validation_assessment", value=validation.model_dump(mode="json"),
                parents=evidence.values(), transformation_id="agenticsoc.validation.v1",
            ))
            stage_latencies["validation"] = (time.perf_counter() - validation_started) * 1000

        decision_started = time.perf_counter()
        decision = final_decision(primary, validation)
        stage_latencies["decision"] = (time.perf_counter() - decision_started) * 1000
        proposals = list(primary.action_proposals)
        if validation is not None:
            proposals.extend(validation.action_proposals)
        policy_start = time.perf_counter()
        action_records = [DryRunAction.model_validate(item) for item in simulate(
            proposals, config.simulated_capabilities,
            enforce=condition is Condition.PTA,
        )]
        stage_latencies["policy"] = (time.perf_counter() - policy_start) * 1000
        amount, currency, basis, cost_complete = _aggregate_cost(calls, config)
        return TrialRecord(
            run_id=str(run_id), case_id=case_id, condition=condition.value, replicate=replicate,
            config_hash=config_hash, input_hash=input_hash,
            dataset_input_sha256=dataset_input_sha256, dataset_gold_sha256=dataset_gold_sha256,
            dataset_manifest_sha256=dataset_manifest_sha256, dataset_version=dataset_version,
            prompt_versions=versions, status="complete", incomplete_reason=None,
            model_calls=len(calls), input_tokens=_token_total(calls, "input_tokens"),
            api_request_count=sum(call.request_attempts for call in calls),
            output_tokens=_token_total(calls, "output_tokens"),
            latency_ms=(time.perf_counter() - started) * 1000,
            per_stage_latency_ms=stage_latencies, call_records=calls,
            cost_amount=amount, cost_currency=currency, cost_basis=basis, cost_complete=cost_complete,
            provider=config.provider, requested_model=config.model,
            returned_models=sorted({call.returned_model for call in calls if call.returned_model}),
            execution_location=getattr(adapter, "execution_location", None),
            runtime_name=getattr(adapter, "runtime_name", None),
            runtime_version=getattr(adapter, "runtime_version", None),
            provider_inference_charge_total=(0.0 if getattr(adapter, "local_execution_confirmed", False) else None),
            provider_inference_charge_basis=(getattr(adapter, "inference_charge_basis", None)
                                             if getattr(adapter, "local_execution_confirmed", False) else None),
            attempted_breach_actions=sum(item.would_breach for item in action_records),
            # A breach is a disallowed action the authorization path would approve.
            # Non-enforcing conditions have no gate, so every disallowed proposal
            # passes through; the PTA gate approves only outcome == "allow".
            approved_breach_actions=sum(
                item.would_breach and (condition is not Condition.PTA or item.outcome == "allow")
                for item in action_records),
            executed_breach_actions=0, primary_assessment=primary, validation_assessment=validation,
            final_verdict=final_decision(primary, validation),
            dissent_detected=validation is not None and primary.assessment.verdict != validation.assessment.verdict,
            assessment_provenance=derived_evidence,
            dry_run_actions=action_records,
        )
    except Exception as exc:
        return _failed_record(run_id=run_id, case_id=case_id, condition=condition.value,
                              replicate=replicate, reason=f"trial error: {type(exc).__name__}: {exc}",
                              started=started, config_hash=config_hash, input_hash=input_hash,
                              versions=versions, calls=calls, dataset_input_sha256=dataset_input_sha256,
                              dataset_gold_sha256=dataset_gold_sha256,
                              dataset_manifest_sha256=dataset_manifest_sha256,
                              dataset_version=dataset_version, model_config=model_config, adapter=adapter)


def _invoke(adapter, request, prompt, config, stage, records):
    started = time.perf_counter()
    prompt_hash = _sha_text(prompt)
    input_tokens = output_tokens = cost = currency = None
    try:
        result = adapter.invoke(request=request, prompt=prompt, config=config, stage=stage)
        input_tokens = getattr(result, "input_tokens", None)
        output_tokens = getattr(result, "output_tokens", None)
        cost = getattr(result, "provider_reported_cost", None)
        currency = getattr(result, "provider_reported_currency", None)
        estimated_cost = getattr(result, "estimated_cost", None)
        estimated_currency = getattr(result, "estimated_currency", None)
        cost_basis = getattr(result, "cost_basis", None)
        request_attempts = getattr(result, "request_attempts", 1)
        returned_model = getattr(result, "returned_model", None)
        execution_location = getattr(result, "execution_location", getattr(adapter, "execution_location", None))
        runtime_name = getattr(result, "runtime_name", getattr(adapter, "runtime_name", None))
        runtime_version = getattr(result, "runtime_version", getattr(adapter, "runtime_version", None))
        inference_charge = getattr(result, "provider_inference_charge", None)
        inference_charge_basis = getattr(result, "provider_inference_charge_basis", None)
        runtime_total_duration_ms = getattr(result, "runtime_total_duration_ms", None)
        runtime_load_duration_ms = getattr(result, "runtime_load_duration_ms", None)
        if type(input_tokens) is not int or input_tokens < 0 or type(output_tokens) is not int or output_tokens < 0:
            raise ValueError("Adapter returned invalid token usage")
        if cost is not None and (type(cost) not in (int, float) or cost < 0):
            raise ValueError("Adapter returned invalid provider-reported cost")
        if cost is not None and (not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency)):
            raise ValueError("Provider cost requires an explicit three-letter currency code")
        if isinstance(result.output, ModelOutput):
            output = result.output
        else:
            output = ModelOutput.model_validate_json(json.dumps(result.output, ensure_ascii=False))
        try:
            _validate_refs(output, request)
        except Exception as exc:
            raise StageValidationError(f"Stage output evidence validation failed: {exc}") from exc
        records.append(ModelCallRecord(stage=stage, prompt_sha256=prompt_hash, status="complete",
                                      latency_ms=(time.perf_counter() - started) * 1000,
                                      input_tokens=input_tokens, output_tokens=output_tokens,
                                      provider_cost=cost, provider_currency=currency,
                                      estimated_cost=estimated_cost, estimated_currency=estimated_currency,
                                      cost_basis=cost_basis, request_attempts=request_attempts,
                                      returned_model=returned_model, execution_location=execution_location,
                                      runtime_name=runtime_name, runtime_version=runtime_version,
                                      provider_inference_charge=inference_charge,
                                      provider_inference_charge_basis=inference_charge_basis,
                                      runtime_total_duration_ms=runtime_total_duration_ms,
                                      runtime_load_duration_ms=runtime_load_duration_ms))
        return output
    except Exception as exc:
        result_exists = "result" in locals()
        estimated_cost = getattr(result, "estimated_cost", None) if result_exists else getattr(exc, "estimated_cost", None)
        estimated_currency = getattr(result, "estimated_currency", None) if result_exists else getattr(exc, "estimated_currency", None)
        cost_basis = getattr(result, "cost_basis", None) if result_exists else None
        request_attempts = getattr(result, "request_attempts", 1) if result_exists else getattr(exc, "request_attempts", 0)
        returned_model = getattr(result, "returned_model", None) if result_exists else getattr(exc, "returned_model", None)
        execution_location = getattr(adapter, "execution_location", None)
        runtime_name = getattr(adapter, "runtime_name", None)
        runtime_version = getattr(adapter, "runtime_version", None)
        inference_charge = getattr(result, "provider_inference_charge", None) if result_exists else None
        inference_charge_basis = getattr(result, "provider_inference_charge_basis", None) if result_exists else None
        runtime_total_duration_ms = getattr(result, "runtime_total_duration_ms", None) if result_exists else None
        runtime_load_duration_ms = getattr(result, "runtime_load_duration_ms", None) if result_exists else None
        if not result_exists and getattr(adapter, "local_execution_confirmed", False) and request_attempts > 0:
            inference_charge = 0.0
            inference_charge_basis = getattr(adapter, "inference_charge_basis", None)
        if not result_exists:
            runtime_total_duration_ms = getattr(exc, "runtime_total_duration_ms", None)
            runtime_load_duration_ms = getattr(exc, "runtime_load_duration_ms", None)
        if input_tokens is None:
            input_tokens = getattr(exc, "input_tokens", None)
        if output_tokens is None:
            output_tokens = getattr(exc, "output_tokens", None)
        records.append(ModelCallRecord(stage=stage, prompt_sha256=prompt_hash, status="incomplete",
                                       latency_ms=(time.perf_counter() - started) * 1000,
                                       input_tokens=input_tokens if type(input_tokens) is int and input_tokens >= 0 else None,
                                       output_tokens=output_tokens if type(output_tokens) is int and output_tokens >= 0 else None,
                                       provider_cost=cost if type(cost) in (int, float) and cost >= 0 else None,
                                       provider_currency=currency,
                                       estimated_cost=estimated_cost if type(estimated_cost) in (int, float) and estimated_cost >= 0 else None,
                                       estimated_currency=estimated_currency, cost_basis=cost_basis,
                                       request_attempts=(request_attempts if type(request_attempts) is int else 0),
                                       returned_model=returned_model,
                                       execution_location=execution_location, runtime_name=runtime_name,
                                       runtime_version=runtime_version,
                                       provider_inference_charge=inference_charge,
                                       provider_inference_charge_basis=inference_charge_basis,
                                       runtime_total_duration_ms=runtime_total_duration_ms,
                                       runtime_load_duration_ms=runtime_load_duration_ms,
                                       failure_kind=getattr(exc, "failure_kind", "malformed" if result_exists else "provider")))
        raise


def _aggregate_cost(calls, config):
    # Every stage must have a per-call amount and all amounts must share currency.
    if calls and all(call.status == "complete" and
                     (call.provider_cost is not None or call.estimated_cost is not None) for call in calls):
        currencies = {
            call.provider_currency if call.provider_cost is not None else call.estimated_currency
            for call in calls
        }
        if len(currencies) == 1 and None not in currencies:
            amount = sum(call.provider_cost if call.provider_cost is not None else call.estimated_cost
                         for call in calls)
            bases = {"provider-reported" if call.provider_cost is not None else "locally estimated"
                     for call in calls}
            basis = " + ".join(sorted(bases)) + " per-call cost"
            return amount, next(iter(currencies)), basis, True
    return None, config.price_currency, "incomplete: at least one per-call cost unavailable and no complete local schedule", False


def run_matrix(*, cases, condition_values, replicates, run_id, config, adapter_factory, order_seed,
               dataset_input_sha256=None, dataset_gold_sha256=None,
               dataset_manifest_sha256=None, dataset_version="agenticsoc-synthetic-v1"):
    """Randomize conditions within paired case/replicate; reset adapter per trial."""
    rng = random.Random(order_seed)
    trials = []
    for case in cases:
        for replicate in range(replicates):
            order = list(condition_values)
            rng.shuffle(order)
            for condition in order:
                try:
                    adapter = adapter_factory()
                except Exception as factory_error:
                    failure = factory_error
                    class FactoryFailure:
                        adapter_version = f"factory-error:{type(failure).__name__}"
                        def invoke(self, **kwargs):
                            raise RuntimeError(f"adapter factory failed: {failure}") from failure
                    adapter = FactoryFailure()
                trials.append(run_trial(
                    case_data=case, condition=condition, replicate=replicate,
                    run_id=run_id, config=config, adapter=adapter,
                    dataset_input_sha256=dataset_input_sha256, dataset_gold_sha256=dataset_gold_sha256,
                    dataset_manifest_sha256=dataset_manifest_sha256, dataset_version=dataset_version,
                ))
    return trials
