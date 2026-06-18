# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.2.0]

### Added
- **Fragile-coverage analysis** — `single_point_techniques()` lists techniques
  covered by exactly one detection (lose that rule, lose the coverage).
- **Dead-rule detection** — `unmapped_detections()` lists detections whose
  technique IDs are all empty/unknown, so they add no coverage.
- A `--json` CLI mode emitting the full report (score, by-tactic, gaps, fragile
  techniques, unmapped detections, unknown IDs); both new findings also appear in
  the text report.

## [0.1.0]

### Added
- Map detections onto a slice of the MITRE ATT&CK Enterprise matrix:
  per-tactic coverage, gaps, an overall score, unknown-technique detection, an
  SVG heatmap, an ATT&CK Navigator layer export, and an `attackcov` CLI.
