# Test262 Compatibility Posture

Current public proof state: checked-in Test262-derived vectors, provisional. This is not a full official Test262 pass-rate claim.

Machine-readable artifact: [`test262_compatibility_pass_rate_v1.json`](test262_compatibility_pass_rate_v1.json)

Current checked-in vector measurement:

| Field | Value |
| --- | --- |
| Proof state | `checked_in_vectors_provisional` |
| Vector source | `precomputed_observed_results` |
| Selected profile | `es2020-normative` |
| Test262 pin | `d0c1b4555b03dd404873fd6422a4b5da00136500` |
| Denominator | `3` |
| Passed | `2` |
| Failed | `0` |
| Waived | `1` |
| Timed out | `0` |
| Crashed | `0` |
| Pass rate | `666666` millionths |

The release-gate artifact validator rejects denominator-zero artifacts and rejects any artifact that attempts to report `full_official_test262` unless it is backed by `official_test262_checkout` evidence with `full_suite_claim_allowed=true`.

Replay script: [`../scripts/e2e/test262_compatibility_pass_rate_replay.sh`](../scripts/e2e/test262_compatibility_pass_rate_replay.sh)
