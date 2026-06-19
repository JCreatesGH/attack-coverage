# attack-coverage

[![CI](https://github.com/JCreatesGH/attack-coverage/actions/workflows/ci.yml/badge.svg)](https://github.com/JCreatesGH/attack-coverage/actions)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Map your detections to the **MITRE ATT&CK** matrix and see exactly where your coverage gaps are — as a heatmap and a per-tactic gap list. Answer "what can't we detect?" with evidence.

![screenshot](assets/screenshot.png)

## Install

```bash
pip install attackcov
```

## Use it

```python
from attackcov import Detection, coverage_by_tactic, gaps, coverage_score, render_svg

detections = [
    Detection("Brute force login", ["T1110"]),
    Detection("Suspicious PowerShell", ["T1059.001"]),   # sub-techniques collapse to T1059
    Detection("Phishing link", ["T1566", "T1204"]),
]

coverage_score(detections)        # 38.5  (% of techniques with >=1 detection)
coverage_by_tactic(detections)    # {"Execution": {"covered": 2, "total": 3, "pct": 66.7}, ...}
gaps(detections)                  # {"Exfiltration": ["T1041", "T1567"], ...}

open("coverage.svg", "w").write(render_svg(detections))

from attackcov import navigator_layer
import json
json.dump(navigator_layer(detections), open("layer.json", "w"))  # import into ATT&CK Navigator
```

## CLI

Installing the package adds an `attackcov` command. Feed it a JSON list of detections
(`[{name, techniques:[...]}]`):

```bash
$ attackcov detections.json                            # coverage %, per-tactic table, gaps, fragile/dead rules
$ attackcov detections.json --json                     # the full report as JSON
$ attackcov detections.json --navigator > layer.json   # MITRE ATT&CK Navigator layer
$ attackcov detections.json --svg > coverage.svg       # heatmap
$ attackcov detections.json --threat ransomware        # coverage vs a specific threat's TTPs
$ attackcov detections.json --min-score 60             # exit 1 if coverage < 60% (CI gate)
```

## Beyond a coverage %

A green-enough score can still hide brittle coverage. `attackcov` also flags:

- **Fragile coverage** — `single_point_techniques()`: techniques covered by exactly *one* detection. If that rule breaks or is disabled, the technique goes dark — the first place to add redundancy.
- **Dead rules** — `unmapped_detections()`: detections whose technique IDs are all empty or unknown, so they add no coverage (usually a typo).

## Are we covered against *this* attacker?

An overall percentage hides whether you can stop the threats that actually matter to you.
`threat_coverage()` scores your detections against a specific adversary's technique set:

```python
from attackcov import threat_coverage, THREAT_PROFILES

threat_coverage(detections, THREAT_PROFILES["ransomware"])
# {"total": 7, "covered": ["T1059", "T1566"], "uncovered": ["T1003", "T1021", ...], "pct": 28.6}
```

On the CLI, `--threat` takes a built-in profile (`ransomware`, `phishing-to-c2`,
`valid-account-abuse`) or a JSON file of technique IDs from your own threat intel, and pairs
with `--min-score` to **gate CI on the threats you care about**:

```bash
$ attackcov detections.json --threat ransomware
Threat coverage (ransomware): 42.9%  (3/7 techniques)
  Uncovered: T1021 Remote Services, T1041 Exfil Over C2, ...
$ attackcov detections.json --threat apt-ttps.json --min-score 80   # exit 1 if under 80%
```

The built-in profiles are illustrative kill-chains built from in-matrix techniques — starting
points, not authoritative MITRE group mappings; supply your own CTI-derived list for real
assessments.

## Notes

- **Sub-techniques collapse** to their parent (`T1059.001` → `T1059`); technique IDs not in the matrix are ignored for scoring but surfaced separately (typo-catcher) via `unknown_techniques`.
- The heatmap colors each technique by **how many** detections cover it (darker green = fewer, grey = none), with a `<title>` tooltip per cell.
- `navigator_layer` produces a v4 layer you can import straight into the **MITRE ATT&CK Navigator**.
- Ships with a compact slice of the ATT&CK Enterprise matrix across 8 tactics; extend `TACTICS` to match your environment.

## Development

```bash
pip install -e .[dev] && python -m pytest -q   # 18 tests
```

## License

MIT
