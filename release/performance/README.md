# Performance evidence

The v0.7.0 baseline is measured from commit
`a390dd9a2210a2e227655a562c541b2b4ebd493c`. Baseline and candidate each
consist of exactly five JSON run files produced on the same pinned runner.
Every file records the immutable runner image, CPU model and CPU set, memory,
storage profile, commit, run index, and the complete metric set enforced by
`tools/check-performance-evidence.py`.

Aggregate a run set with:

```sh
python3 tools/check-performance-evidence.py aggregate \
  --kind baseline --output release/performance/baseline.json \
  run-1.json run-2.json run-3.json run-4.json run-5.json
```

Candidate evidence uses `--kind candidate`. Compare both aggregates with:

```sh
python3 tools/check-performance-evidence.py compare \
  --baseline release/performance/baseline.json \
  --candidate release/performance/candidate.json \
  --output release/performance/comparison.json
```

The checker rejects partial metric sets, mixed commits, duplicate run numbers,
runner drift, non-finite measurements, every violated absolute limit, and the
relative median/p95 regression limits. Each aggregate remains cryptographically
bound to all five adjacent source-run files; comparisons re-hash and recompute
those runs instead of trusting hand-edited summary values. Strict `<` thresholds
also reject equality, while `at most` thresholds accept it. No placeholder
aggregate is committed: qualification remains open until real pinned-runner and
CIFS measurements are archived.
