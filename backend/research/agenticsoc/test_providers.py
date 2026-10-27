"""Offline tests for hosted-API adapters and the API runner. Fake clients only."""

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

from .live_adapter import LiveAdapterError, LiveRunBudget
from .providers import (
    JSON_OBJECT_SUFFIX, AnthropicMessagesAdapter, OpenAICompatibleChatAdapter, make_adapter,
)
from .run_api import preflight, run
from .pilot import PACKAGE
from .schema import ModelConfig, ModelRequest

CONFIG = PACKAGE / "configs" / "api-anthropic-real-loghub.json"


def _reply(user_json, verdict="malicious", actions=()):
    request = json.loads(user_json)
    event = request["events"][0]
    return json.dumps({
        "assessment": {"assessor": "fake", "verdict": verdict,
                       "evidence_refs": [{"event_id": event["event_id"],
                                          "field_path": event["fields"][0]["field_path"]}],
                       "rationale": "fake"},
        "action_proposals": [{"action": a, "target": "host", "rationale": "fake"} for a in actions],
    })


class FakeAnthropic:
    def __init__(self, stop_reason="end_turn", text=None, actions=()):
        self.calls = []
        self.stop_reason, self.text, self.actions = stop_reason, text, actions
        self.messages = SimpleNamespace(create=self.create)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        body = self.text if self.text is not None else _reply(kwargs["messages"][0]["content"], actions=self.actions)
        return SimpleNamespace(
            model=kwargs["model"], stop_reason=self.stop_reason, stop_details=None,
            content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=body)],
            usage=SimpleNamespace(input_tokens=1000, output_tokens=200))


class FakeChat:
    def __init__(self, finish_reason="stop"):
        self.calls = []
        self.finish_reason = finish_reason
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.calls.append(kwargs)
        message = SimpleNamespace(content=_reply(kwargs["messages"][1]["content"]), refusal=None)
        return SimpleNamespace(model=kwargs["model"], choices=[SimpleNamespace(message=message,
                               finish_reason=self.finish_reason)],
                               usage=SimpleNamespace(prompt_tokens=500, completion_tokens=100))


def _config(provider="anthropic", **overrides):
    data = dict(provider=provider, model="test-model", temperature=None, reasoning_effort=None,
                max_output_tokens=1024, input_price_per_million=4.0, output_price_per_million=20.0,
                price_schedule_id="test", price_currency="USD", simulated_capabilities=["search_logs"])
    data.update(overrides)
    return ModelConfig.model_validate(data)


def _request():
    return ModelRequest.model_validate({
        "task": "assess", "events": [{"event_id": "evt-1", "source_type": "syslog", "timestamp": "2026-01-01T00:00:00Z",
                                       "fields": [{"field_path": "message", "value": "hello"}]}]})


def _budget(**kw):
    return LiveRunBudget(max_requests=kw.get("max_requests", 10), hard_budget=kw.get("hard_budget", 5.0),
                         currency="USD")


class AnthropicAdapterTests(unittest.TestCase):
    def test_success_records_usage_cost_and_sends_no_tools_or_sampling(self):
        client = FakeAnthropic()
        adapter = AnthropicMessagesAdapter(budget=_budget(), client=client)
        result = adapter.invoke(request=_request(), prompt="sys", config=_config(reasoning_effort="low"),
                                stage="analysis")
        self.assertEqual(result.output.assessment.verdict.value, "malicious")
        self.assertEqual((result.input_tokens, result.output_tokens), (1000, 200))
        self.assertAlmostEqual(result.estimated_cost, (1000 * 4 + 200 * 20) / 1e6)
        sent = client.calls[0]
        self.assertNotIn("tools", sent)
        self.assertNotIn("temperature", sent)
        self.assertNotIn("fallbacks", sent)
        self.assertEqual(sent["output_config"]["effort"], "low")
        self.assertEqual(sent["output_config"]["format"]["type"], "json_schema")

    def test_refusal_truncation_and_malformed_output_fail_closed(self):
        for client, kind in ((FakeAnthropic(stop_reason="refusal"), "refused"),
                             (FakeAnthropic(stop_reason="max_tokens"), "provider"),
                             (FakeAnthropic(text="not json"), "malformed")):
            adapter = AnthropicMessagesAdapter(budget=_budget(), client=client)
            with self.assertRaises(LiveAdapterError) as ctx:
                adapter.invoke(request=_request(), prompt="sys", config=_config(), stage="analysis")
            self.assertEqual(ctx.exception.failure_kind, kind)
            self.assertEqual(ctx.exception.input_tokens, 1000)

    def test_missing_credential_blocks_before_any_request(self):
        import os
        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(LiveAdapterError):
                AnthropicMessagesAdapter(budget=_budget())
        finally:
            if saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = saved

    def test_budget_stops_requests(self):
        adapter = AnthropicMessagesAdapter(budget=_budget(max_requests=1), client=FakeAnthropic())
        adapter.invoke(request=_request(), prompt="sys", config=_config(), stage="analysis")
        with self.assertRaises(LiveAdapterError) as ctx:
            adapter.invoke(request=_request(), prompt="sys", config=_config(), stage="analysis")
        self.assertEqual(ctx.exception.failure_kind, "budget")


class OpenAICompatibleTests(unittest.TestCase):
    def test_json_schema_provider_uses_strict_schema(self):
        client = FakeChat()
        adapter = OpenAICompatibleChatAdapter(provider="gemini", budget=_budget(), client=client)
        adapter.invoke(request=_request(), prompt="sys", config=_config("gemini"), stage="analysis")
        self.assertEqual(client.calls[0]["response_format"]["type"], "json_schema")
        self.assertEqual(client.calls[0]["messages"][0]["content"], "sys")

    def test_json_object_provider_appends_schema_and_truncation_fails(self):
        client = FakeChat()
        adapter = make_adapter("deepseek", budget=_budget(), timeout_seconds=5, max_retries=0,
                               retry_delay_seconds=0, client=client)
        adapter.invoke(request=_request(), prompt="sys", config=_config("deepseek"), stage="analysis")
        self.assertEqual(client.calls[0]["messages"][0]["content"], "sys" + JSON_OBJECT_SUFFIX)
        truncated = OpenAICompatibleChatAdapter(provider="groq", budget=_budget(), client=FakeChat("length"))
        with self.assertRaises(LiveAdapterError):
            truncated.invoke(request=_request(), prompt="sys", config=_config("groq"), stage="analysis")

    def test_unknown_provider_rejected(self):
        with self.assertRaises(ValueError):
            make_adapter("nope", budget=_budget(), timeout_seconds=5, max_retries=0, retry_delay_seconds=0)


class ApiRunnerTests(unittest.TestCase):
    def _args(self, out, report, **overrides):
        args = Namespace(config=CONFIG, output_dir=out, run_id="test-run", execute=True,
                         confirm_provider="anthropic", confirm_model="claude-opus-5-5",
                         confirm_max_requests=144, confirm_budget=20.0,
                         confirm_fingerprint=report["pilot_fingerprint"])
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_preflight_makes_no_requests_and_plans_72_calls(self):
        report = preflight(CONFIG)
        self.assertEqual(report["network_requests"], 0)
        self.assertEqual(report["planned_stage_calls"], 72)
        self.assertFalse(report["execution_authorized"])

    def test_run_requires_matching_confirmations(self):
        report = preflight(CONFIG)
        with tempfile.TemporaryDirectory() as out:
            with self.assertRaises(ValueError):
                run(self._args(out, report, confirm_fingerprint="wrong"), client=FakeAnthropic())
            with self.assertRaises(ValueError):
                run(self._args(out, report, execute=False), client=FakeAnthropic())

    def test_end_to_end_with_fake_client_writes_scored_artifacts(self):
        report = preflight(CONFIG)
        client = FakeAnthropic(actions=("delete_evidence",))
        with tempfile.TemporaryDirectory() as out:
            result = run(self._args(out, report), client=client, pace=False)
            self.assertEqual(len(client.calls), 72)
            self.assertEqual(result["incomplete_trials"], 0)
            evaluation = json.loads(Path(result["evaluation_artifact"]).read_text(encoding="utf-8"))
            conditions = evaluation["conditions"]
            # Every reply proposes delete_evidence: baselines are breached, the PTA gate is not.
            self.assertEqual(conditions["PTA"]["cbr"]["numerator"], 0)
            self.assertEqual(conditions["Baseline-None"]["cbr"]["numerator"],
                             conditions["Baseline-None"]["cbr"]["denominator"])
            trials = [json.loads(line) for line in Path(result["trial_artifact"]).read_text(encoding="utf-8").splitlines()]
            self.assertTrue(all(a["executed"] is False for t in trials for a in t["dry_run_actions"]))
            self.assertTrue(Path(result["tables_markdown"]).is_file())


if __name__ == "__main__":
    unittest.main()
