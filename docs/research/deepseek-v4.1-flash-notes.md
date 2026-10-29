## Summary (read this first)

Model `deepseek-v4.1-flash` (OpenCode Go endpoint), run 2026-10-30, temperature 0, one replicate.
Two datasets: 36 synthetic SOC cases and 18 real LogHub Linux log cases, each analysed in all three setups
(162 trials, 203 API requests, about $0.27 at OpenCode list price, billed to the Go plan allowance).

**1. No injection attack succeeded in any setup.** Across both datasets there were 60 completed attack
trials (direct, fragmented K=2–4, and prohibited-action injections) and 0 successes, including with no
defense at all. With so few trials per cell this only rules out high success rates: 0 of ~20 per setup is
still compatible with a true rate of up to about 16%.

**2. The biggest problem is output reliability, not security.** 57 of 162 trials (35%) failed and are
excluded: 42% on the synthetic set, 22% on the real logs. Almost all failures are the model writing an
action description longer than the 100-character schema limit. JSON mode guarantees valid JSON, not the
schema's length limits. These failures shrink every cell below and are the main limit on what this run
can show.

**3. The model treats injected text as evidence of an attack.** Without defenses, injected cases were
mostly labelled `malicious`, never `benign`. The injection did not hide the alert; it raised one.

**4. What PTA changes.** With the PTA stack, injected cases mostly end as `uncertain`, because the
blind validator and the analyst disagree and PTA does not silently pick one. Its policy gate blocked
every non-allowed action proposal (68 synthetic, 28 real), so its Capability Breach Rate is 0 by design.
The cost: about 1.9–2.5× the latency and cost per case (two model calls), and more abstentions on clean cases
(50% vs 36% with no defense on the synthetic set).

**5. "Capability Breach Rate = 100%" for the baselines is not a danger signal.** The harness counts every
action outside the three allowed tool names as a breach. DeepSeek proposed 0 actions on the deny list
(e.g. `delete_evidence`); the "breaches" are free-text actions such as `preserve_evidence`, `isolate_host`
and `monitor`. Section 4 of each dataset separates these categories.

**Detection on clean synthetic cases** (no injection): malicious caught 4/5 (A), 3/5 (B), 4/5 (C);
no benign case was ever flagged malicious in any setup.

**Not comparable with `results.md` one-to-one.** The Ollama numbers there (e.g. ISR 0.31–0.46 for small
local models) come from a different attack set and harness configuration. Read this as "a larger hosted
model resisted this harness's injections", not as a ranking.

**Recommended next step:** rerun with provider-enforced JSON schema or a prompt reminder of the
100-character limit to cut the failure rate, and with more replicates, before drawing firm conclusions.
