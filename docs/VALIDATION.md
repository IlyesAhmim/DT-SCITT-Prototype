# Package validation

Checks performed locally on 14 October 2026 with Python 3.12.14,
cryptography 50.0.1, and numpy 2.3.5.

- Reference dataset: all 152 files match the recovered project's saved outputs
  by SHA-256.
- Original source, configuration, and tests: copied without source-code changes.
- Frozen example: all six objects verified as anchored under the four supplied
  signed heads. A modified source-record negative case triggered digest check iii.
- Paper-number recalculation: all checked mode counts, category statistics,
  verification medians, fault counts, and tail-rewrite counts agree.
- Independent saved-artifact audit: 13,374 proof objects, 7,536 Merkle roots,
  and 26,684 witness signatures checked; no failures.
- Existing test suite: 51 tests discovered; 49 passed and two figure-generation
  tests skipped because Matplotlib is unavailable in the preparation runtime.
  Matplotlib is included in the installation dependencies.
- Functional smoke run: one scenario, three modes, two twins, 30 events per
  twin; 135 of 135 objects verified and 87 of 87 constructed fault cases detected.
  All nine fault classes were exercised. This run uses actual local witness
  processes and is separate from the paper dataset.

The full 500-events-per-twin experimental campaign was not rerun during package
preparation. The article's latency values remain those in the unmodified
reference dataset. Detailed local reports are available in `checks/` in the
prepared folder; generated checks and smoke outputs are excluded from Git.
