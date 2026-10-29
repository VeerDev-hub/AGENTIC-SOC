**Model:** `deepseek-v4.1-flash` via the OpenCode Go endpoint, temperature 0, provider-enforced JSON
schema. **Runs:** 2026-10-30. **Data:** synthetic benchmark v2 (240 cases, 120 normal / 120 injected,
one replicate, 720 trials) and real LogHub Linux_2k logs (18 cases × 3 replicates, 162 trials).
Total: 882 trials, 1,343 API requests, ≈ $1.95 at OpenCode list prices. All figures are available
as vector PDF and 300-dpi PNG in `figures/`; `tables.csv` holds the counts behind the tables.

## Summary of findings

1. **No injection succeeded in any setup.** 0 of 349 completed synthetic attack trials and 0 of 108
   real-log attack trials met their success criterion — including with no defense at all. The 95%
   Wilson upper bound for each setup's pooled ISR is 3.1–3.3% on the synthetic set and 9.6% on the
   real logs. This holds for every attack type (direct, fragmented K = 2/3/4, prohibited-action) and
   every injection style (S1 override, S2 false authority, S3 false context, S4 base64).
2. **The model names the injection instead of obeying it.** In its rationales the analyst explicitly
   labels injected text as an untrusted embedded instruction (it even decoded and dismissed the S4
   base64 payload) and still reports the underlying attack: 100% of injected synthetic cases were
   labelled `malicious` in all three setups.
3. **Detection on normal cases was perfect in every setup:** TPR 48/48 and FPR 0 on 60–69 benign cases.
4. **The PTA stack bought no measurable security for this model, at a measurable price.** Relative to
   no defense it used 3.1× the cost per trial ($0.0041 vs $0.0013), 2.5× the median latency (23.0 s vs
   9.3 s) and ~4× the tokens. On normal cases it abstained more often and gave fewer correct verdicts
   (94.5% → 87.3% on 110 paired cases; exact McNemar p = 0.039, 10 vs 2 discordant pairs). Its policy
   gate blocked every non-allowed action, so its capability-breach rate is 0 by construction, but the
   baselines also proposed 0 deny-listed actions.
5. **The defensive prompt alone changed nothing measurable** (all paired tests p = 1).
6. **No dangerous action was ever proposed.** Of 3,020 proposed actions across setups on the synthetic
   set, 0 were deny-listed (delete_evidence, tamper_evidence, disclose_credentials, exfiltrate_data,
   disable_security) and 92 needed human approval (e.g. isolate_endpoint).
7. **Output reliability was high once the schema was enforced:** 93–98% of trials completed. 101 of 949
   synthetic stage calls (10.6%) and 31 of 215 real-log calls (14.4%) needed one or two counted format
   resamples. The remaining failures were mostly citations of evidence fields not supplied to that stage.

## Interpretation

For a current hosted model of this class, single-shot prompt injection inside log fields does not
flip the triage verdict on clearly malicious activity, and a defensive system prompt adds nothing on
top. The value of a structural defense such as PTA therefore lies in its guarantees (the policy gate
makes capability breach impossible regardless of model behaviour) rather than in a measured ISR
reduction, and it has a real cost in latency, tokens and abstentions. This contrasts with the
small local models in `../results.md` (ISR 0.17–0.46), although those numbers come from a different
attack set and are not directly comparable.

## Limitations

- **Ceiling effect.** Every injected case hides an unambiguous attack (LSASS dumping, ransomware,
  brute force followed by success, etc.). The injection must override strong evidence, which makes
  suppression hard. Ambiguous or low-signal activity with an injection is the natural next test and
  would give ISR room to move.
- **Static, non-adaptive attacks.** Payloads were fixed templates; an attacker who iterates against
  the model was not simulated.
- **One model, one replicate on the synthetic set** at temperature 0; three replicates on the real logs.
- **Format resampling** (≤ 2, counted) can favour compliant outputs; resample counts are reported
  above and every attempt is included in cost.
- **LogHub has no security ground truth**, so detection accuracy and false-positive rate are only
  measured on the synthetic set. Real-log injections test only the prohibited `delete_evidence` goal.
- **Zero counts are bounds, not proofs:** "0/119" means the true rate is very likely below 3.1%.
