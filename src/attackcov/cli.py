"""Command-line interface: report ATT&CK coverage from a detections JSON file."""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Optional

from .coverage import (Detection, coverage_by_tactic, gaps, coverage_score,
                       unknown_techniques, single_point_techniques, unmapped_detections)
from .heatmap import render_svg
from .navigator import navigator_layer


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attackcov", description="Report MITRE ATT&CK detection coverage and gaps.")
    parser.add_argument("file", nargs="?",
                        help="JSON: a list of {name, techniques:[...]} (or {detections:[...]}); default stdin")
    parser.add_argument("--svg", action="store_true", help="emit the coverage heatmap SVG")
    parser.add_argument("--navigator", action="store_true", help="emit a MITRE ATT&CK Navigator layer (JSON)")
    parser.add_argument("--json", action="store_true", help="emit the coverage report as JSON")
    parser.add_argument("--min-score", type=float, default=None,
                        help="exit 1 if overall coverage %% is below this (CI gate)")
    args = parser.parse_args(argv)

    raw = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON: {e}", file=sys.stderr)
        return 2
    records = data["detections"] if isinstance(data, dict) and "detections" in data else data
    if not isinstance(records, list):
        print("error: expected a JSON list of detections (or {detections: [...]})", file=sys.stderr)
        return 2

    dets = [Detection(r.get("name", ""), r.get("techniques", [])) for r in records]

    if args.navigator:
        print(json.dumps(navigator_layer(dets), indent=2))
        return 0
    if args.svg:
        print(render_svg(dets))
        return 0

    score = coverage_score(dets)
    fragile = single_point_techniques(dets)
    unmapped = unmapped_detections(dets)
    unknown = unknown_techniques(dets)

    if args.json:
        print(json.dumps({
            "coverage_score": score,
            "by_tactic": coverage_by_tactic(dets),
            "gaps": gaps(dets),
            "single_point_techniques": fragile,
            "unmapped_detections": unmapped,
            "unknown_techniques": unknown,
        }, indent=2))
        return 1 if (args.min_score is not None and score < args.min_score) else 0

    print(f"ATT&CK coverage: {score}%")
    for tactic, s in coverage_by_tactic(dets).items():
        print(f"  {tactic:<22} {s['covered']}/{s['total']}  ({s['pct']}%)")
    g = gaps(dets)
    if g:
        print("\nGaps (uncovered techniques):")
        for tactic, ids in g.items():
            print(f"  {tactic}: {', '.join(ids)}")
    if fragile:
        print(f"\n⚠ Fragile coverage (single detection): {', '.join(fragile)}")
    if unmapped:
        print(f"\n⚠ Detections mapping to no known technique: {', '.join(unmapped)}")
    if unknown:
        print(f"\n⚠ Unknown technique IDs (not in matrix): {', '.join(unknown)}")

    return 1 if (args.min_score is not None and score < args.min_score) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
