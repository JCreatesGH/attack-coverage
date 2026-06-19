# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/).

## [0.3.0]

### Added
- **Per-threat coverage** — `threat_coverage(detections, technique_ids)` scores your detections
  against a specific adversary's technique set (the actionable "can we detect THIS attacker?"),
  collapsing sub-techniques and de-duping. Ships three illustrative kill-chain profiles
  (`THREAT_PROFILES`: ransomware, phishing-to-c2, valid-account-abuse) — starting points, not
  authoritative MITRE group mappings.
- CLI `--threat NAME|FILE` takes a built-in profile or a JSON file of technique IDs, and pairs
  with `--min-score` to gate CI on a specific threat's coverage.

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
