"""Local-only adapter for the native Ollama HTTP API.

The endpoint is deliberately fixed to IPv4 loopback. This module never reads
provider API keys, environment proxy settings, remote URLs, or cloud fallbacks.
It does not install or pull models and registers no tools.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import (HTTPRedirectHandler, ProxyHandler, Request, build_opener)

from .adapter import AdapterResult
from .schema import ModelConfig, ModelOutput, ModelRequest


LOCAL_BASE_URL = "http://127.0.0.1:11434"
LOCAL_ENDPOINT_ID = "ollama.loopback.v1"
ADAPTER_VERSION = "ollama-local-adapter.v1"
INFERENCE_CHARGE_BASIS = (
    "confirmed local Ollama inference; provider API inference charge is zero; "
    "electricity, hardware, and model acquisition costs are excluded"
)


class LocalAdapterError(RuntimeError):
    failure_kind = "provider"

    def __init__(self, message, *, request_attempts=0, returned_model=None,
                 input_tokens=None, output_tokens=None, failure_kind=None,
                 runtime_total_duration_ms=None, runtime_load_duration_ms=None):
        super().__init__(message)
        self.request_attempts = request_attempts
        self.returned_model = returned_model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.runtime_total_duration_ms = runtime_total_duration_ms
        self.runtime_load_duration_ms = runtime_load_duration_ms
        if failure_kind:
            self.failure_kind = failure_kind


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LocalAdapterError("Redirects from the configured loopback Ollama endpoint are forbidden")


def validate_loopback_url(value: str = LOCAL_BASE_URL) -> str:
    """Accept only plain HTTP to the exact IPv4 loopback address and port."""
    from urllib.parse import urlsplit

    parts = urlsplit(value)
    try:
        address = ipaddress.ip_address(parts.hostname or "")
    except ValueError as exc:
        raise ValueError("Ollama endpoint must use the literal IPv4 loopback address") from exc
    if (parts.scheme != "http" or address != ipaddress.ip_address("127.0.0.1") or
            parts.port != 11434 or parts.username or parts.password or parts.path or
            parts.query or parts.fragment):
        raise ValueError("Only http://127.0.0.1:11434 is permitted for local Ollama")
    return LOCAL_BASE_URL


def _default_transport(method: str, path: str, payload: dict | None, timeout: float):
    url = validate_loopback_url(LOCAL_BASE_URL) + path
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = Request(url, data=data, method=method,
                      headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data is not None else {})})
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise LocalAdapterError(f"Local Ollama returned HTTP {exc.code}", request_attempts=1) from exc
    except URLError as exc:
        raise LocalAdapterError(f"Cannot reach local Ollama endpoint: {exc.reason}", request_attempts=1) from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LocalAdapterError("Local Ollama returned invalid JSON", request_attempts=1,
                                failure_kind="malformed") from exc


@dataclass(frozen=True)
class LocalRuntimeInfo:
    endpoint: str
    version: str
    model_tag: str
    model_digest: str

    def __post_init__(self):
        validate_loopback_url(self.endpoint)
        if not self.version.strip() or not self.model_tag.strip() or not self.model_digest.strip():
            raise ValueError("Local runtime confirmation requires version, exact model tag, and digest")


def _is_cloud_tag(tag: str) -> bool:
    return "cloud" in tag.lower().replace("_", "-").split(":")[-1].split("-")


def _validate_model_tag(tag: str) -> None:
    if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", tag):
        raise ValueError("Model tag must be a bounded, unpadded Ollama identifier")
    if _is_cloud_tag(tag):
        raise ValueError("Ollama cloud model tags are forbidden")


def preflight_local_runtime(*, model_tag: str, timeout: float = 3.0, transport=None) -> LocalRuntimeInfo:
    """Confirm a loopback runtime and an already-installed exact model tag.

    Makes only GET /api/version and GET /api/tags; it performs no inference,
    model pull, or configuration mutation.
    """
    validate_loopback_url(LOCAL_BASE_URL)
    _validate_model_tag(model_tag)
    get = transport or _default_transport
    version_data = get("GET", "/api/version", None, timeout)
    tags_data = get("GET", "/api/tags", None, timeout)
    if not isinstance(version_data, dict) or not isinstance(version_data.get("version"), str):
        raise LocalAdapterError("Local Ollama version response is malformed", failure_kind="malformed")
    models = tags_data.get("models") if isinstance(tags_data, dict) else None
    if not isinstance(models, list):
        raise LocalAdapterError("Local Ollama tags response is malformed", failure_kind="malformed")
    matches = [item for item in models if isinstance(item, dict) and item.get("name") == model_tag]
    if len(matches) != 1 or _is_cloud_tag(model_tag):
        raise ValueError(f"Exact non-cloud model tag {model_tag!r} is not installed locally; no model was pulled")
    digest = matches[0].get("digest")
    if not isinstance(digest, str) or not digest.strip():
        raise LocalAdapterError("Local model tag has no digest in /api/tags", failure_kind="malformed")
    return LocalRuntimeInfo(LOCAL_BASE_URL, version_data["version"], model_tag, digest)


def _schema_for_ollama():
    # Ollama's native API accepts a JSON Schema object in `format`. The returned
    # content is still parsed by Pydantic strictly; no repair or coercion occurs.
    return ModelOutput.model_json_schema()


class OllamaLocalAdapter:
    adapter_version = ADAPTER_VERSION
    execution_location = "local"
    runtime_name = "ollama"
    local_execution_confirmed = True
    inference_charge_basis = INFERENCE_CHARGE_BASIS

    def __init__(self, *, runtime: LocalRuntimeInfo, timeout_seconds: float = 180.0,
                 context_window_tokens: int = 8192, seed: int = 20261024, transport=None):
        if not isinstance(runtime, LocalRuntimeInfo):
            raise TypeError("A successful local preflight result is required")
        self.runtime = runtime
        self.runtime_version = runtime.version
        self.model_tag = runtime.model_tag
        fingerprint_data = {
            "endpoint_id": LOCAL_ENDPOINT_ID, "endpoint": runtime.endpoint,
            "runtime": runtime.version, "model_tag": runtime.model_tag,
            "model_digest": runtime.model_digest, "adapter": ADAPTER_VERSION,
            "context_window_tokens": context_window_tokens, "seed": seed,
        }
        self.configuration_fingerprint = hashlib.sha256(json.dumps(
            fingerprint_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest()
        self.timeout_seconds = timeout_seconds
        if type(context_window_tokens) is not int or context_window_tokens < 1024:
            raise ValueError("context_window_tokens must be an integer of at least 1024")
        if type(seed) is not int or seed < 0:
            raise ValueError("seed must be a non-negative integer")
        self.context_window_tokens = context_window_tokens
        self.seed = seed
        self.transport = transport or _default_transport

    def invoke(self, *, request: ModelRequest, prompt: str, config: ModelConfig, stage: str) -> AdapterResult:
        if config.provider != "ollama" or config.model != self.model_tag:
            raise ValueError("Local adapter requires the exact preflighted Ollama model configuration")
        _validate_model_tag(config.model)
        visible_request = request.model_dump(mode="json", exclude_none=True)
        user_content = json.dumps(visible_request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        payload = {
            "model": self.model_tag,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": user_content},
            ],
            "stream": False,
            "format": _schema_for_ollama(),
            "options": {"temperature": config.temperature if config.temperature is not None else 0.0,
                        "num_predict": config.max_output_tokens,
                        "num_ctx": self.context_window_tokens, "seed": self.seed},
        }
        try:
            raw = self.transport("POST", "/api/chat", payload, self.timeout_seconds)
        except LocalAdapterError:
            raise
        except Exception as exc:
            raise LocalAdapterError(f"Local Ollama request failed: {type(exc).__name__}: {exc}",
                                    request_attempts=1) from exc
        returned_model = raw.get("model") if isinstance(raw, dict) else None
        prompt_tokens = raw.get("prompt_eval_count") if isinstance(raw, dict) else None
        output_tokens = raw.get("eval_count") if isinstance(raw, dict) else None
        total_duration = raw.get("total_duration") if isinstance(raw, dict) else None
        load_duration = raw.get("load_duration") if isinstance(raw, dict) else None
        common = {"request_attempts": 1, "returned_model": returned_model,
                  "input_tokens": prompt_tokens if type(prompt_tokens) is int and prompt_tokens >= 0 else None,
                  "output_tokens": output_tokens if type(output_tokens) is int and output_tokens >= 0 else None,
                  "runtime_total_duration_ms": (total_duration / 1_000_000 if type(total_duration) is int and total_duration >= 0 else None),
                  "runtime_load_duration_ms": (load_duration / 1_000_000 if type(load_duration) is int and load_duration >= 0 else None)}
        if (not isinstance(raw, dict) or raw.get("done") is not True or
                returned_model != self.model_tag):
            raise LocalAdapterError("Ollama response is incomplete or returned a different model tag",
                                    failure_kind="malformed", **common)
        message = raw.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LocalAdapterError("Ollama response has no assistant message content",
                                    failure_kind="malformed", **common)
        try:
            output = ModelOutput.model_validate_json(content)
        except Exception as exc:
            raise LocalAdapterError(f"Ollama output failed strict ModelOutput validation: {exc}",
                                    failure_kind="malformed", **common) from exc
        if (type(prompt_tokens) is not int or prompt_tokens < 0 or
                type(output_tokens) is not int or output_tokens < 0):
            raise LocalAdapterError("Ollama response omitted valid token usage counts",
                                    failure_kind="malformed", **common)
        return AdapterResult(
            output=output, input_tokens=prompt_tokens, output_tokens=output_tokens,
            request_attempts=1, returned_model=returned_model,
            execution_location="local", runtime_name="ollama", runtime_version=self.runtime.version,
            provider_inference_charge=0.0,
            provider_inference_charge_basis=INFERENCE_CHARGE_BASIS,
            runtime_total_duration_ms=(total_duration / 1_000_000 if type(total_duration) is int and total_duration >= 0 else None),
            runtime_load_duration_ms=(load_duration / 1_000_000 if type(load_duration) is int and load_duration >= 0 else None),
        )
