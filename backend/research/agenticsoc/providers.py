"""Hosted-API provider adapters behind one interface.

Every adapter makes exactly one budgeted stage call, registers no tools, and
validates the reply against the local ModelOutput schema. Base URLs are fixed
here, never taken from configuration, so a config file cannot redirect
requests. Credentials are read only from the environment variable named in
PROVIDERS and are never copied into records or output.

Supported providers:
  anthropic   - official Anthropic SDK, Messages API with structured output
  openai      - existing OpenAI Responses adapter (live_adapter.py)
  gemini, deepseek, groq, mistral, openrouter
              - OpenAI-compatible Chat Completions via the OpenAI SDK
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version

from .adapter import AdapterResult
from .live_adapter import (
    LiveAdapterError, LiveRunBudget, OpenAIResponsesAdapter, _failure_kind, _is_retryable, _output_schema,
)
from .schema import ModelConfig, ModelOutput, ModelRequest


@dataclass(frozen=True)
class ProviderSpec:
    env_var: str
    sdk: str
    base_url: str | None = None
    # "json_schema": provider enforces the schema; "json_object": provider only
    # guarantees JSON, so the schema is appended to the system prompt.
    structured_output: str = "json_schema"


PROVIDERS = {
    "anthropic": ProviderSpec("ANTHROPIC_API_KEY", "anthropic"),
    "openai": ProviderSpec("OPENAI_API_KEY", "openai"),
    "gemini": ProviderSpec("GEMINI_API_KEY", "openai",
                           "https://generativelanguage.googleapis.com/v1beta/openai/"),
    "deepseek": ProviderSpec("DEEPSEEK_API_KEY", "openai", "https://api.deepseek.com",
                             structured_output="json_object"),
    "groq": ProviderSpec("GROQ_API_KEY", "openai", "https://api.groq.com/openai/v1"),
    "mistral": ProviderSpec("MISTRAL_API_KEY", "openai", "https://api.mistral.ai/v1"),
    "openrouter": ProviderSpec("OPENROUTER_API_KEY", "openai", "https://openrouter.ai/api/v1"),
}

JSON_OBJECT_SUFFIX = ("\n\nReturn only one JSON object that conforms to this JSON Schema:\n" +
                      json.dumps(_output_schema(), sort_keys=True, separators=(",", ":")))


def provider_spec(provider: str) -> ProviderSpec:
    try:
        return PROVIDERS[provider]
    except KeyError:
        raise ValueError(f"Unsupported provider {provider!r}; choose one of {sorted(PROVIDERS)}") from None


def sdk_version(provider: str) -> str | None:
    try:
        return version(provider_spec(provider).sdk)
    except PackageNotFoundError:
        return None


def effective_prompt(provider: str, prompt: str) -> str:
    """The exact system text sent, so preflight cost estimates match the run."""
    return prompt + JSON_OBJECT_SUFFIX if provider_spec(provider).structured_output == "json_object" else prompt


def _request_json(request: ModelRequest) -> str:
    return json.dumps(request.model_dump(mode="json", exclude_none=True),
                      sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class _BudgetedAdapter:
    """Shared retry, budget, usage, and validation handling."""

    adapter_version = "budgeted-adapter.v1"

    def __init__(self, *, provider: str, budget: LiveRunBudget, timeout_seconds: float = 60.0,
                 max_retries: int = 1, retry_delay_seconds: float = 1.0, client=None):
        if timeout_seconds <= 0 or max_retries < 0 or retry_delay_seconds < 0:
            raise ValueError("Timeout must be positive and retry settings non-negative")
        self.provider = provider
        self.spec = provider_spec(provider)
        self.budget = budget
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds
        if client is None and not os.environ.get(self.spec.env_var):
            raise LiveAdapterError("provider", f"{self.spec.env_var} is not set")
        self.client = client if client is not None else self._make_client()
        self.sdk_version = sdk_version(provider)

    def _make_client(self):
        raise NotImplementedError

    def _call(self, *, system: str, user: str, config: ModelConfig):
        raise NotImplementedError

    def _parse(self, response, config: ModelConfig):
        """Return (text, input_tokens, output_tokens, returned_model, problem)."""
        raise NotImplementedError

    def invoke(self, *, request: ModelRequest, prompt: str, config: ModelConfig, stage: str) -> AdapterResult:
        if config.provider != self.provider:
            raise LiveAdapterError("provider", f"Adapter for {self.provider!r} received provider {config.provider!r}")
        system = effective_prompt(self.provider, prompt)
        user = _request_json(request)
        reserved = 0.0
        attempts = 0
        response = None
        for retry in range(self.max_retries + 1):
            reserved += self.budget.authorize_request(
                request_bytes=len((system + user).encode("utf-8")),
                output_token_cap=config.max_output_tokens, config=config,
            )
            attempts += 1
            try:
                response = self._call(system=system, user=user, config=config)
                break
            except Exception as exc:
                if retry >= self.max_retries or not _is_retryable(exc):
                    raise LiveAdapterError(_failure_kind(exc), f"Provider request failed ({type(exc).__name__})",
                                           attempts=attempts) from exc
                time.sleep(self.retry_delay_seconds * (2 ** retry))

        text, input_tokens, output_tokens, returned_model, problem = self._parse(response, config)
        valid_usage = (type(input_tokens) is int and input_tokens >= 0 and
                       type(output_tokens) is int and output_tokens >= 0)
        # Cost is estimated from returned usage and the configured local price
        # schedule. A retried call has unknown cost for the failed attempt.
        estimated_cost = ((input_tokens * config.input_price_per_million +
                           output_tokens * config.output_price_per_million) / 1_000_000
                          if valid_usage and attempts == 1 else None)
        failure = dict(attempts=attempts, input_tokens=input_tokens if valid_usage else None,
                       output_tokens=output_tokens if valid_usage else None,
                       estimated_cost=estimated_cost, currency=config.price_currency,
                       returned_model=returned_model)
        if problem is not None:
            kind, message = problem
            raise LiveAdapterError(kind, message, **failure)
        try:
            output = ModelOutput.model_validate_json(text or "")
        except Exception as exc:
            raise LiveAdapterError("malformed", "Provider output did not match the research schema",
                                   **failure) from exc
        if not valid_usage:
            raise LiveAdapterError("provider", "Provider response omitted valid token usage", **failure)
        return AdapterResult(
            output=output, input_tokens=input_tokens, output_tokens=output_tokens,
            estimated_cost=estimated_cost,
            estimated_currency=config.price_currency if estimated_cost is not None else None,
            cost_basis=(f"usage-estimated from local price schedule {config.price_schedule_id}; "
                        f"pre-call budget reservation {reserved:.8f} {self.budget.currency}"
                        if estimated_cost is not None else
                        f"incomplete: {attempts} requests, prior attempt cost unavailable; "
                        f"reservation {reserved:.8f} {self.budget.currency}"),
            request_attempts=attempts, returned_model=returned_model, execution_location="remote",
        )


class AnthropicMessagesAdapter(_BudgetedAdapter):
    """Claude via the official SDK. No tools, no refusal fallback.

    A server-side refusal fallback would answer with a different model and mix
    two models inside one comparison, so refusals stay recorded as incomplete.
    Sampling parameters are not sent: current Claude models reject them.
    """

    adapter_version = "anthropic-messages-adapter.v1"
    execution_location = "remote"

    def __init__(self, **kwargs):
        super().__init__(provider="anthropic", **kwargs)

    def _make_client(self):
        import anthropic
        # max_retries=0: every HTTP attempt is counted and budgeted here.
        return anthropic.Anthropic(timeout=self.timeout_seconds, max_retries=0)

    def _call(self, *, system, user, config):
        output_config = {"format": {"type": "json_schema", "schema": _output_schema()}}
        if config.reasoning_effort is not None:
            output_config["effort"] = config.reasoning_effort
        return self.client.messages.create(
            model=config.model, max_tokens=config.max_output_tokens, system=system,
            messages=[{"role": "user", "content": user}], output_config=output_config,
        )

    def _parse(self, response, config):
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "input_tokens", None)
        output_tokens = getattr(usage, "output_tokens", None)
        returned_model = getattr(response, "model", None)
        stop = getattr(response, "stop_reason", None)
        problem = None
        if stop == "refusal":
            details = getattr(response, "stop_details", None)
            problem = ("refused", f"Provider refused the assessment (category={getattr(details, 'category', None)})")
        elif stop == "max_tokens":
            problem = ("provider", "Response hit max_output_tokens before completing")
        text = next((block.text for block in getattr(response, "content", []) or []
                     if getattr(block, "type", None) == "text"), None)
        return text, input_tokens, output_tokens, returned_model, problem


class OpenAICompatibleChatAdapter(_BudgetedAdapter):
    """Chat Completions on a fixed provider base URL (Gemini, DeepSeek, Groq, ...)."""

    adapter_version = "openai-compatible-chat-adapter.v1"
    execution_location = "remote"

    def _make_client(self):
        from openai import OpenAI
        return OpenAI(api_key=os.environ[self.spec.env_var], base_url=self.spec.base_url,
                      timeout=self.timeout_seconds, max_retries=0)

    def _call(self, *, system, user, config):
        if self.spec.structured_output == "json_schema":
            response_format = {"type": "json_schema", "json_schema": {
                "name": "agenticsoc_assessment", "strict": True, "schema": _output_schema()}}
        else:
            response_format = {"type": "json_object"}
        args = dict(model=config.model, max_tokens=config.max_output_tokens, response_format=response_format,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
        if config.temperature is not None:
            args["temperature"] = config.temperature
        if config.reasoning_effort is not None:
            args["reasoning_effort"] = config.reasoning_effort
        return self.client.chat.completions.create(**args)

    def _parse(self, response, config):
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "prompt_tokens", None)
        output_tokens = getattr(usage, "completion_tokens", None)
        returned_model = getattr(response, "model", None)
        choices = getattr(response, "choices", None) or []
        if not choices:
            return None, input_tokens, output_tokens, returned_model, ("provider", "Provider returned no choices")
        message = choices[0].message
        problem = None
        if getattr(message, "refusal", None):
            problem = ("refused", "Provider refused the assessment")
        elif choices[0].finish_reason == "length":
            problem = ("provider", "Response hit max_output_tokens before completing")
        elif choices[0].finish_reason == "content_filter":
            problem = ("refused", "Provider content filter blocked the response")
        return message.content, input_tokens, output_tokens, returned_model, problem


def make_adapter(provider: str, *, budget: LiveRunBudget, timeout_seconds: float, max_retries: int,
                 retry_delay_seconds: float, client=None):
    """Build a fresh adapter for one trial; no conversation state is shared."""
    common = dict(budget=budget, timeout_seconds=timeout_seconds, max_retries=max_retries,
                  retry_delay_seconds=retry_delay_seconds, client=client)
    spec = provider_spec(provider)
    if provider == "anthropic":
        return AnthropicMessagesAdapter(**common)
    if provider == "openai":
        return OpenAIResponsesAdapter(**common)
    if spec.base_url is not None:
        return OpenAICompatibleChatAdapter(provider=provider, **common)
    raise ValueError(f"No adapter registered for {provider!r}")


def adapter_version(provider: str) -> str:
    if provider == "anthropic":
        return AnthropicMessagesAdapter.adapter_version
    if provider == "openai":
        return OpenAIResponsesAdapter.adapter_version
    provider_spec(provider)
    return OpenAICompatibleChatAdapter.adapter_version
