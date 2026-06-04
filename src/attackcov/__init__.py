"""attackcov: map detections to MITRE ATT&CK techniques and chart coverage gaps."""
from .matrix import TACTICS, Technique, all_techniques, technique_name
from .coverage import map_detections, coverage_by_tactic, gaps, coverage_score, Detection
from .heatmap import render_svg
__all__ = ["TACTICS", "Technique", "all_techniques", "technique_name",
           "map_detections", "coverage_by_tactic", "gaps", "coverage_score",
           "Detection", "render_svg"]
__version__ = "0.1.0"
