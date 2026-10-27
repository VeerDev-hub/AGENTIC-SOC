"""Opt-in OpenAI Responses adapter for isolated synthetic research trials.

Importing this module and constructing an adapter with an injected test client
does not make a network request. Credentials are read only by the SDK client
from OPENAI_API_KEY; they are never copied into experiment records.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

from .adapter import AdapterResult
from .schema import ModelConfig, ModelOutput, ModelRequest


class LiveAdapterError(RuntimeError):
    def __init__(self, kind: str, message: str, *, attempts: int = 0, input_tokens=None,
                 output_tokens=None, estimated_cost=None, currency=None, returned_model=None):
        super().__init__(message)
        self.failure_kind = kind
        self.request_attempts = attempts
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.estimated_cost = estimated_cost
        self.estimated_currency = currency
        self.returned_model = returned_model


class LiveRunBudget:
    """Shared run-wide request, spend-reservation, and pacing guard."""

    def __init__(self, *, max_requests: int, hard_budget: float, currency: str,
                 minimum_interval_seconds: float = 0.0, framing_token_reserve: int = 512):
        if max_requests < 1 or hard_budget <= 0 or len(currency) != 3 or not currency.isalpha():
            raise ValueError("Live budget requires positive request/spend limits and an explicit currency")
        if minimum_interval_seconds < 0 or framing_token_reserve < 0:
            raise ValueError("Rate and framing limits must be non-negative")
        self.max_requests = max_requests
        self.hard_budget = hard_budget
        self.currency = currency.upper()
        self.minimum_interval_seconds = minimum_interval_seconds
        self.framing_token_reserve = framing_token_reserve
        self.request_count = 0
        self.reserved_cost = 0.0
        self._last_request_at: float | None = None
        self._lock = threading.Lock()

    def authorize_request(self, *, request_bytes: int, output_token_cap: int, config: ModelConfig) -> float:
        if config.input_price_per_million is None or config.output_price_per_million is None:
            raise LiveAdapterError("budget", "A local price schedule is required for live budget enforcement")
        if config.price_currency != self.currency:
            raise LiveAdapterError("budget", "The run budget and model price schedule currencies differ")
        max_input_tokens = request_bytes + self.framing_token_reserve
        reserve = (max_input_tokens * config.input_price_per_million +
                   output_token_cap * config.output_price_per_million) / 1_000_000
        with self._lock:
            if self.request_count >= self.max_requests:
                raise LiveAdapterError("budget", "Maximum live request count reached")
            if self.reserved_cost + reserve > self.hard_budget:
                raise LiveAdapterError("budget", "Next request would exceed the configured hard budget")
            wait = 0.0
            if self._last_request_at is not None:
                wait = max(0.0, self.minimum_interval_seconds - (time.monotonic() - self._last_request_at))
            if wait:
                time.sleep(wait)
            self._last_request_at = time.monotonic()
            self.request_count += 1
            self.reserved_cost += reserve
        return reserve


def _failure_kind(exc: Exception) -> str:
    name = type(exc).__name__.lower()
    if "timeout" in name:
        return "timeout"
    if "ratelimit" in name or getattr(exc, "status_code", None) == 429:
        return "rate_limit"
    status = getattr(exc, "status_code", None)
    if status in (408, 409) or (isinstance(status, int) and status >= 500):
        return "provider"
    if "connection" in name:
        return "provider"
    return "provider"


def _is_retryable(exc: Exception) -> bool:
    kind = _failure_kind(exc)
    status = getattr(exc, "status_code", None)
    return kind in {"timeout", "rate_limit"} or status in (408, 409) or (
        isinstance(status, int) and status >= 500
    ) or "connection" in type(exc).__name__.lower()


def _refused(response) -> bool:
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", None) == "refusal" or getattr(content, "refusal", None):
                return True
    return False


def _output_schema() -> dict:
    """Provider-compatible strict schema for the existing typed output."""
    ref = {
        "type": "object", "additionalProperties": False,
        "properties": {"event_id": {"type": "string"}, "field_path": {"type": "string"}},
        "required": ["event_id", "field_path"],
    }
    proposal = {
        "type": "object", "additionalProperties": False,
        "properties": {"action": {"type": "string"}, "target": {"type": "string"},
                       "rationale": {"type": "string"}},
        "required": ["action", "target", "rationale"],
    }
    assessment = {
        "type": "object", "additionalProperties": False,
        "properties": {"assessor": {"type": "string"},
                       "verdict": {"type": "string", "enum": ["benign", "malicious", "uncertain"]},
                       "evidence_refs": {"type": "array", "items": ref},
                       "rationale": {"type": "string"}},
        "required": ["assessor", "verdict", "evidence_refs", "rationale"],
    }
    return {
        "type": "object", "additionalProperties": False,
        "properties": {"assessment": assessment,
                       "action_proposals": {"type": "array", "items": proposal}},
        "required": ["assessment", "action_proposals"],
    }


@dataclass
class OpenAIResponsesAdapter:
    """One model stage call; no tools are registered and no real action can run."""

    budget: LiveRunBudget
    timeout_seconds: float = 45.0
    max_retries: int = 1
    client: object | None = None
    retry_delay_seconds: float = 0.5

    adapter_version = "openai-responses-adapter.v1"
    sdk_version: str | None = None

    def __post_init__(self):
        if self.timeout_seconds <= 0 or self.max_retries < 0 or self.retry_delay_seconds < 0:
            raise ValueError("Timeout must be positive and retry settings non-negative")
        if self.client is None:
            if not os.environ.get("OPENAI_API_KEY"):
                raise LiveAdapterError("provider", "OPENAI_API_KEY is not set")
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise LiveAdapterError("provider", "Locked OpenAI SDK is unavailable") from exc
            # Disable hidden SDK retries so every HTTP attempt is budgeted and counted here.
            self.client = OpenAI(timeout=self.timeout_seconds, max_retries=0)
        try:
            self.sdk_version = version("openai")
        except PackageNotFoundError:
            self.sdk_version = None

    def invoke(self, *, request: ModelRequest, prompt: str, config: ModelConfig, stage: str) -> AdapterResult:
        if config.provider != "openai":
            raise LiveAdapterError("provider", "OpenAI adapter requires provider='openai'")
        request_json = json.dumps(request.model_dump(mode="json", exclude_none=True),
                                  sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        input_payload = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": request_json},
        ]
        reserved = 0.0
        response = None
        attempts = 0
        for retry in range(self.max_retries + 1):
            reserved += self.budget.authorize_request(
                request_bytes=len((prompt + request_json).encode("utf-8")),
                output_token_cap=config.max_output_tokens, config=config,
            )
            attempts += 1
            try:
                request_args = dict(
                    model=config.model,
                    input=input_payload,
                    max_output_tokens=config.max_output_tokens,
                    text={"format": {"type": "json_schema", "name": "agenticsoc_assessment",
                                     "strict": True, "schema": _output_schema()}},
                    timeout=self.timeout_seconds,
                )
                if config.temperature is not None and config.reasoning_effort is None:
                    request_args["temperature"] = config.temperature
                if config.reasoning_effort is not None:
                    request_args["reasoning"] = {"effort": config.reasoning_effort}
                response = self.client.responses.create(**request_args)
                break
            except Exception as exc:
                if retry >= self.max_retries or not _is_retryable(exc):
                    raise LiveAdapterError(_failure_kind(exc), f"Provider request failed ({type(exc).__name__})",
                                           attempts=attempts) from exc
                time.sleep(self.retry_delay_seconds * (2 ** retry))

        if response is None:
            raise LiveAdapterError("provider", "Provider returned no response", attempts=attempts)
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "input_tokens", None)
        output_tokens = getattr(usage, "output_tokens", None)
        valid_usage = (type(input_tokens) is int and input_tokens >= 0 and
                       type(output_tokens) is int and output_tokens >= 0)
        estimated_cost = ((input_tokens * config.input_price_per_million +
                           output_tokens * config.output_price_per_million) / 1_000_000
                          if valid_usage and attempts == 1 else None)
        returned_model = getattr(response, "model", None)
        if _refused(response):
            raise LiveAdapterError("refused", "Provider refused the assessment", attempts=attempts,
                                   input_tokens=input_tokens if valid_usage else None,
                                   output_tokens=output_tokens if valid_usage else None,
                                   estimated_cost=estimated_cost, currency=config.price_currency,
                                   returned_model=returned_model)
        if getattr(response, "status", None) == "incomplete":
            raise LiveAdapterError("provider", "Provider returned an incomplete response", attempts=attempts,
                                   input_tokens=input_tokens if valid_usage else None,
                                   output_tokens=output_tokens if valid_usage else None,
                                   estimated_cost=estimated_cost, currency=config.price_currency,
                                   returned_model=returned_model)
        output_text = getattr(response, "output_text", None)
        try:
            output = ModelOutput.model_validate_json(output_text)
        except Exception as exc:
            raise LiveAdapterError("malformed", "Provider output did not match the research schema",
                                   attempts=attempts, input_tokens=input_tokens if valid_usage else None,
                                   output_tokens=output_tokens if valid_usage else None,
                                   estimated_cost=estimated_cost, currency=config.price_currency,
                                   returned_model=returned_model) from exc
        if type(input_tokens) is not int or type(output_tokens) is not int or input_tokens < 0 or output_tokens < 0:
            raise LiveAdapterError("provider", "Provider response omitted valid token usage", attempts=attempts)
        return AdapterResult(
            output=output, input_tokens=input_tokens, output_tokens=output_tokens,
            estimated_cost=estimated_cost, estimated_currency=config.price_currency if estimated_cost is not None else None,
            cost_basis=(f"usage-estimated from local price schedule {config.price_schedule_id}; "
                        f"pre-call budget reservation {reserved:.8f} {self.budget.currency}"
                        if estimated_cost is not None else
                        f"incomplete: {attempts} requests, prior attempt cost unavailable; "
                        f"reservation {reserved:.8f} {self.budget.currency}"),
            request_attempts=attempts, returned_model=getattr(response, "model", None),
        )
