"""Compute coverage of the matrix from a set of detections."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set
from .matrix import TACTICS, all_techniques


@dataclass
class Detection:
    name: str
    techniques: List[str]    # ATT&CK technique IDs this detection covers


def map_detections(detections: List[Detection]) -> Dict[str, int]:
    """technique_id -> number of detections covering it (valid IDs only)."""
    valid = set(all_techniques())
    counts: Dict[str, int] = {}
    for d in detections:
        for tid in d.techniques:
            base = tid.split(".")[0]          # collapse sub-techniques T1059.001 -> T1059
            if base in valid:
                counts[base] = counts.get(base, 0) + 1
    return counts


def coverage_by_tactic(detections: List[Detection]) -> Dict[str, Dict[str, float]]:
    counts = map_detections(detections)
    out: Dict[str, Dict[str, float]] = {}
    for tactic, techs in TACTICS.items():
        covered = sum(1 for t in techs if counts.get(t.id, 0) > 0)
        out[tactic] = {"covered": covered, "total": len(techs),
                       "pct": round(100 * covered / len(techs), 1)}
    return out


def gaps(detections: List[Detection]) -> Dict[str, List[str]]:
    """tactic -> technique IDs with zero detections."""
    counts = map_detections(detections)
    out: Dict[str, List[str]] = {}
    for tactic, techs in TACTICS.items():
        missing = [t.id for t in techs if counts.get(t.id, 0) == 0]
        if missing:
            out[tactic] = missing
    return out


def coverage_score(detections: List[Detection]) -> float:
    counts = map_detections(detections)
    total = len(all_techniques())
    covered = sum(1 for tid in all_techniques() if counts.get(tid, 0) > 0)
    return round(100 * covered / total, 1) if total else 0.0


def unknown_techniques(detections: List[Detection]) -> List[str]:
    """Referenced technique IDs that aren't in the matrix — catches typos and
    techniques outside the configured scope."""
    valid = set(all_techniques())
    out: Set[str] = set()
    for d in detections:
        for tid in d.techniques:
            if tid.split(".")[0] not in valid:
                out.add(tid)
    return sorted(out)
