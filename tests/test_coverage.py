from attackcov import (Detection, map_detections, coverage_by_tactic, gaps,
                       coverage_score, unknown_techniques, single_point_techniques,
                       unmapped_detections, threat_coverage, THREAT_PROFILES,
                       render_svg, navigator_layer)
from attackcov.cli import main


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


def test_unknown_techniques():
    assert unknown_techniques(DETS) == ["T9999"]      # the invalid one is surfaced
    assert unknown_techniques([Detection("ok", ["T1110"])]) == []


def test_single_point_techniques():
    # every covered technique in DETS has exactly one detection -> all fragile
    assert single_point_techniques(DETS) == ["T1059", "T1110", "T1204", "T1566"]
    # add a second detection for T1110 -> no longer single-point
    dets = DETS + [Detection("Another brute force rule", ["T1110"])]
    assert "T1110" not in single_point_techniques(dets)


def test_unmapped_detections():
    assert unmapped_detections(DETS) == ["Junk"]              # only T9999
    assert unmapped_detections([Detection("ok", ["T1110"])]) == []
    assert unmapped_detections([Detection("empty", [])]) == ["empty"]


def test_threat_coverage_basic():
    # DETS covers T1110, T1059, T1204, T1566
    rep = threat_coverage(DETS, ["T1566", "T1059.001", "T1041", "T1003"])
    assert rep["total"] == 4                              # collapsed + de-duped
    assert rep["covered"] == ["T1059", "T1566"]
    assert rep["uncovered"] == ["T1003", "T1041"]
    assert rep["pct"] == 50.0


def test_threat_coverage_dedupes_and_collapses():
    rep = threat_coverage(DETS, ["T1059", "T1059.001", "T1059.003"])
    assert rep["total"] == 1 and rep["covered"] == ["T1059"] and rep["pct"] == 100.0


def test_threat_profiles_are_in_matrix():
    from attackcov import all_techniques
    valid = set(all_techniques())
    for name, techs in THREAT_PROFILES.items():
        assert all(t in valid for t in techs), f"{name} has an out-of-matrix technique"


def test_cli_threat_report(tmp_path, capsys):
    import json
    f = tmp_path / "dets.json"
    f.write_text(json.dumps([{"name": "Brute force", "techniques": ["T1110"]},
                             {"name": "PS", "techniques": ["T1059"]}]))
    # against the ransomware profile, T1110 isn't in it but T1059 is; expect partial coverage
    code = main([str(f), "--threat", "ransomware", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert code == 0
    assert rep["threat"] == "ransomware" and "T1059" in rep["covered"]
    assert 0 < rep["pct"] < 100


def test_cli_threat_min_score_gate(tmp_path, capsys):
    import json
    f = tmp_path / "dets.json"
    f.write_text(json.dumps([{"name": "PS", "techniques": ["T1059"]}]))
    # low ransomware coverage; gate at 80% -> exit 1
    assert main([str(f), "--threat", "ransomware", "--min-score", "80"]) == 1


def test_cli_threat_unknown_profile(tmp_path, capsys):
    import json
    f = tmp_path / "dets.json"
    f.write_text(json.dumps([{"name": "x", "techniques": ["T1110"]}]))
    assert main([str(f), "--threat", "not-a-profile-or-file"]) == 2
    assert "built-in profile" in capsys.readouterr().err


def test_navigator_layer():
    layer = navigator_layer(DETS, name="My Coverage")
    assert layer["name"] == "My Coverage"
    assert layer["domain"] == "enterprise-attack"
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1110"]["score"] == 1               # covered
    assert by_id["T1041"]["score"] == 0               # gap (exfil)
    assert "T9999" not in by_id                        # invalid IDs aren't in the matrix
    assert layer["gradient"]["maxValue"] >= 1


def test_cli_report_and_min_score(tmp_path, capsys):
    import json
    f = tmp_path / "dets.json"
    f.write_text(json.dumps([
        {"name": "Brute force", "techniques": ["T1110"]},
        {"name": "PS", "techniques": ["T1059.001"]},
        {"name": "typo", "techniques": ["T9999"]},
    ]))
    code = main([str(f), "--min-score", "90"])         # coverage is far below 90%
    out = capsys.readouterr().out
    assert code == 1
    assert "ATT&CK coverage:" in out
    assert "Unknown technique IDs" in out and "T9999" in out


def test_cli_navigator_output(tmp_path, capsys):
    import json
    f = tmp_path / "dets.json"
    f.write_text(json.dumps({"detections": [{"name": "x", "techniques": ["T1110"]}]}))
    assert main([str(f), "--navigator"]) == 0
    layer = json.loads(capsys.readouterr().out)
    assert layer["versions"]["layer"] == "4.5"


def test_cli_json_output(tmp_path, capsys):
    import json
    f = tmp_path / "dets.json"
    f.write_text(json.dumps([
        {"name": "Brute force", "techniques": ["T1110"]},
        {"name": "typo", "techniques": ["T9999"]},
    ]))
    assert main([str(f), "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert "coverage_score" in rep
    assert rep["single_point_techniques"] == ["T1110"]
    assert rep["unmapped_detections"] == ["typo"]
    assert rep["unknown_techniques"] == ["T9999"]
