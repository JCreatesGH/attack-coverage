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


def single_point_techniques(detections: List[Detection]) -> List[str]:
    """Techniques covered by exactly one detection — fragile coverage: if that
    rule breaks or is disabled, the technique goes dark. The first place to add
    redundancy."""
    return sorted(tid for tid, n in map_detections(detections).items() if n == 1)


def unmapped_detections(detections: List[Detection]) -> List[str]:
    """Names of detections that map to no known technique (all IDs empty or
    invalid) — they add no coverage and are usually a typo or dead rule."""
    valid = set(all_techniques())
    return [d.name for d in detections
            if not any(tid.split(".")[0] in valid for tid in d.techniques)]


# Illustrative kill-chain technique sets (in-matrix IDs only). These are starting
# points for "are we covered against THIS?", NOT authoritative MITRE group mappings —
# pass your own CTI-derived technique list for a real adversary assessment.
THREAT_PROFILES: Dict[str, List[str]] = {
    "ransomware": ["T1566", "T1059", "T1547", "T1003", "T1021", "T1562", "T1041"],
    "phishing-to-c2": ["T1566", "T1204", "T1059", "T1547", "T1041"],
    "valid-account-abuse": ["T1078", "T1098", "T1021", "T1567"],
}


def threat_coverage(detections: List[Detection], threat_techniques: List[str]) -> Dict[str, object]:
    """Coverage against a specific adversary/threat's technique set — the actionable
    question "can we detect THIS attacker?". Sub-techniques collapse to their base;
    duplicates are de-duped in first-seen order. Returns covered / uncovered / pct."""
    counts = map_detections(detections)
    bases: List[str] = []
    seen: Set[str] = set()
    for tid in threat_techniques:
        b = str(tid).split(".")[0]
        if b not in seen:
            seen.add(b)
            bases.append(b)
    covered = sorted(b for b in bases if counts.get(b, 0) > 0)
    uncovered = sorted(b for b in bases if counts.get(b, 0) == 0)
    pct = round(100 * len(covered) / len(bases), 1) if bases else 0.0
    return {"total": len(bases), "covered": covered, "uncovered": uncovered, "pct": pct}
