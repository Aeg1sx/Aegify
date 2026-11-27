# Grading saved AI source reviews

The fixture asks the same question about three functions. Does the returned mapping include a top-level `customer_email` field? One function returns the field, one returns a different set of keys, and one calls an unspecified formatter. The labels contain the expected verdict, source hash and complete function range. They are stored separately from the source and the review runner.

The recorded Codex CLI 0.166.0 run made six model calls and three source reads. All three verdicts matched the labels. The indirect return received `needs_review` with the missing formatter named as the gap. The runner supplies the same bounded reading task for each case and does not send the labels to the provider. This checks the review protocol on three authored examples. Independent application-review quality, confidence calibration, the provider-selected model identity and billing remain unmeasured.

## Grade the saved run offline

```bash
uv run --project scanner --locked aegify benchmark-reviews \
  scanner/benchmarks/source-review-v1/codex-reviews.json \
  --labels scanner/benchmarks/source-review-v1/labels.json \
  --source-root receipts=scanner/benchmarks/source-review-v1/sources \
  --output-file /tmp/aegify-review-grades.json
```

The evaluator binds the review to its source manifest, checks returned citations against the issued tool record and frozen excerpt, and checks the cited range and rationale for a directional verdict. Every manifest label contributes to the agreement denominator. Exit `0` meets the agreement threshold, `1` misses it, `2` indicates invalid input, and `3` indicates missing evidence or incomplete analysis.

## Repeat with a configured provider

This opt-in run uses an authenticated Codex CLI, makes up to two model calls per case and uses an empty temporary working directory. Only the owned receipt fixture supplies source content. Run the offline grading command above with the new artifact to measure the new answers.

```bash
uv run --project scanner --locked python \
  scanner/benchmarks/source-review-v1/review_fixture.py \
  --output /tmp/aegify-receipt-reviews.json
```

`codex-grades.json` and `codex-reviews.json` retain the score and input for the three judgments. `codex-protocol.json` records a separate six-role conformance run with twelve provider calls on an owned string fixture.
