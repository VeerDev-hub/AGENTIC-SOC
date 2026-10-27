# Local Ollama pilot (proposed; not authorized)

This is a separate execution path for the isolated synthetic research harness.
It does not alter the OpenAI adapter or production SOC code. The frozen 60-case
dataset, evaluator-only gold data, scoring definitions, and three conditions
remain the same. This document and `ollama-pilot-proposed.json` are a proposal;
no model inference or pilot has been run.

## Local-only boundary

`ollama_adapter.py` uses Ollama's native `POST /api/chat` endpoint at the fixed
literal address `http://127.0.0.1:11434`. It does not accept a base URL from
configuration, follow redirects, use environment proxy settings, read API
credentials, register tools, pull models, or switch providers/models. It
requires a successful local preflight and the exact model tag and digest
returned by Ollama's local `/api/tags`. Tags containing a cloud marker are
rejected. Responses whose returned model tag differs from the configured tag
are incomplete. A missing server, missing model, HTTP error, malformed JSON,
invalid Pydantic output, or omitted token counts is recorded as a failed call;
the adapter never repairs an output or falls back to a paid API.

The adapter sends `POST /api/chat` with `model`, `messages`,
`"stream": false`, `format` set to `ModelOutput.model_json_schema()`, and fixed
generation options (`temperature`, `num_predict`, `num_ctx`, and `seed`). It
reads `message.content`, then validates it with strict
`ModelOutput.model_validate_json`. Ollama's documented response also includes
`model`, `done`, `prompt_eval_count`, `eval_count`, `total_duration`, and
`load_duration`; the harness records token counts, exact returned tag, client
latency, and Ollama-reported generation/load durations when present. There is
no `tools` property in the request. The official API documents the request,
JSON Schema `format`, response usage counts and durations at
[Ollama chat API](https://docs.ollama.com/api/chat). Structured output via a
JSON Schema is described in the [Ollama structured outputs guide](https://ollama.com/blog/structured-outputs).

The request's user content is the serialized typed model request: task plus
one evidence representation. It never contains evaluator gold labels,
objectives, fragment counts, expected verdicts, sentinels, or evaluator
configuration. The PTA validator receives the same event evidence and prompt
for its own stage, without seeing the primary assessment. All proposed
actions remain within the shared dry-run simulator; no real tool is available.

The adapter itself only connects to loopback and cannot select a cloud URL or
provider. Ollama is a separate process, so for a strict no-egress pilot, block
outbound internet access for the Ollama runtime at the host firewall while
keeping loopback available. Do not use cloud-suffixed model tags. Model
download is a separate setup step; the experiment runner never downloads a
model. Confirm via `/api/tags` that the selected exact tag is installed before
starting the pilot.

## Hardware and model proposal

At implementation time, this Windows host reported an NVIDIA GeForce RTX 4060
Laptop GPU with 8,188 MiB VRAM and 15.7 GiB installed RAM. Available RAM was
about 1.3 GiB at that moment, so memory pressure should be reduced before
loading a model. Hardware availability is not a performance measurement and
can change with other processes.

The proposed starting tag is
`qwen3:4b-instruct-2507-q4_K_M`. Ollama's model library lists this quantized
tag at about 2.5 GB; the 4B size is a conservative starting point on this
machine, with an 8,192-token context limit configured to bound KV-cache use.
The model file size is not the full runtime memory requirement. Close memory-
heavy applications and confirm adequate free RAM before loading it. The
Ollama tag listing includes the exact tag and published size at
[Qwen3 tags](https://ollama.com/library/qwen3/tags). If the actual machine has
less available memory, start with a smaller quantized Qwen3 tag and re-review
the pilot fingerprint/config before any run. Do not silently change model
tags mid-run. No local quality or security result is implied by this choice.

## Install and verify locally

Install Ollama for Windows using its official installer. In a PowerShell
terminal, download the proposed model separately (this is a model download,
not an inference call):

```powershell
ollama --version
ollama pull qwen3:4b-instruct-2507-q4_K_M
ollama list
```

Confirm `ollama list` shows the exact tag above. Ensure Ollama is running, then
check only the two metadata endpoints (these are GET requests and do not run a
model):

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/version
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

The API shapes are `{ "version": "..." }` from `GET /api/version` and a
`{ "models": [...] }` response from `GET /api/tags`; see the official
[version endpoint source](https://github.com/ollama/ollama/blob/main/docs/api.md#version)
and [list models API](https://docs.ollama.com/api/tags). The harness binds
the endpoint to the loopback literal so DNS, proxy variables, and cloud API
base URLs cannot redirect its own HTTP client. It makes no request to
`ollama.com` during preflight or inference.

From the repository's backend directory, first run offline checks (no Ollama
HTTP request):

```powershell
cd backend
uv sync --frozen
.\.venv\Scripts\python.exe -m research.agenticsoc.ollama_preflight --offline
```

Then the safe local preflight makes exactly two localhost metadata GETs and no
inference calls. It verifies the dataset and reports the installed runtime,
exact model digest, selected cases, planned calls, checksums, and a fingerprint:

```powershell
.\.venv\Scripts\python.exe -m research.agenticsoc.ollama_preflight
```

The preflight always reports `execution_authorized: false`. It neither pulls
models nor writes a run artifact. Re-run and review the preflight after any
model, runtime, dataset, prompt, schema, policy, seed, or config change.

## Proposed pilot and explicit gate

The proposed sample selects 3 cases from each of the 6 existing scenario
strata (18 cases total), one replicate, with the existing deterministic case
selection and randomized condition order. The 3 baselines each make one model
call per case; PTA makes an analysis call and a separate blind validation
call. The plan therefore has 72 model calls before incomplete trials. There
are no retries. All conditions use the same exact local model tag,
temperature 0, 1,024 output-token cap, 8,192 context, seed 20261024, task,
schema, simulated capabilities, and scoring. PTA's additional call and its
latency/token usage are recorded per call and included in end-to-end totals.

Condition definitions remain:

- **Baseline-None:** existing neutral prompt with no PTA controls.
- **Baseline-Prompt:** existing defensive prompt only; its text is not
  deterministic enforcement.
- **PTA:** field-level T2 provenance, untrusted evidence handling, blind
  independent validation, explicit disagreement handling, and deterministic
  dry-run policy checks.

Results are written to the separate `results-local/` directory. The local
runner refuses to score a set containing another provider, model tag, or
execution location. Run metadata and each trial state `provider: ollama` and
`execution_location: local`; runtime version and returned tag are recorded.
Configuration/run fingerprints cover dataset checksums, model tag and local
digest, runtime version, generation settings, exact prompt hashes and
versions, adapter, schema, evaluator, and policy versions. The fixed run
artifacts must be kept separate from OpenAI or other-provider results; do not
pool them as direct comparisons without a separately approved design.

The `provider_inference_charge_total` is reported as zero only after local
runtime/model confirmation and for requests sent through the fixed loopback
adapter. Its currency is intentionally null because no provider billing
currency applies. Electricity, hardware depreciation, and model download/data
costs are excluded. The existing generic monetary-cost metric remains
incomplete when it has no currency-based price schedule; it must not be
misreported as an all-in cost of zero.

No FRR(K) is calculated; its paper definition remains unresolved. ISR, false
positive rate, CBR, denominator caveats, and dissent handling use the existing
research contract without changes. CBR remains Capability Breach Rate with
its denominator provisional. Local-model results are not evidence of
production safety, and mock tests are not research measurements.

The live-local runner requires every confirmation below plus the preflight
fingerprint. This is an execution approval boundary, not a command to run now.
Do not run it until the pilot configuration, hardware readiness, firewall
policy, dataset checksums, and exact local model tag have been reviewed and
approved:

```powershell
.\.venv\Scripts\python.exe -m research.agenticsoc.run_ollama `
  --execute-local-pilot `
  --confirm-execution-location local `
  --confirm-provider ollama `
  --confirm-model qwen3:4b-instruct-2507-q4_K_M `
  --confirm-max-model-calls 72 `
  --confirm-fingerprint <fingerprint-from-local-preflight>
```

No live-local run was made while implementing this adapter. Tests use mocked
responses only:

```powershell
.\.venv\Scripts\python.exe manage.py test research.agenticsoc
```
