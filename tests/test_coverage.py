from attackcov import (Detection, map_detections, coverage_by_tactic, gaps,
                       coverage_score, render_svg)


DETS = [
    Detection("Brute force login", ["T1110"]),
    Detection("Suspicious PowerShell", ["T1059.001"]),   # sub-technique collapses to T1059
    Detection("Phishing link click", ["T1566", "T1204"]),
    Detection("Junk", ["T9999"]),                        # invalid, ignored
]


def test_map_collapses_subtech_and_drops_invalid():
    counts = map_detections(DETS)
    assert counts["T1059"] == 1          # from T1059.001
    assert "T9999" not in counts
    assert counts["T1566"] == 1


def test_coverage_by_tactic():
    cov = coverage_by_tactic(DETS)
    assert cov["Credential Access"]["covered"] == 1     # T1110
    assert cov["Execution"]["covered"] == 2             # T1059, T1204
    assert cov["Exfiltration"]["covered"] == 0


def test_gaps():
    g = gaps(DETS)
    assert "Exfiltration" in g
    assert "T1041" in g["Exfiltration"]
    assert "Credential Access" in g                     # T1003, T1555 missing


def test_coverage_score():
    score = coverage_score(DETS)
    assert 0 < score < 100


def test_render_svg():
    svg = render_svg(DETS)
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "T1110" in svg and "<title>" in svg
