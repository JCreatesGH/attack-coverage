"""Render the ATT&CK matrix as an SVG coverage heatmap."""
from __future__ import annotations
from typing import Dict, List
from .matrix import TACTICS
from .coverage import map_detections, Detection

_COL_W, _CELL_H, _GAP, _HEAD = 150, 30, 4, 40


def _color(count: int) -> str:
    if count == 0:
        return "#2d333b"
    if count == 1:
        return "#0e4429"
    if count == 2:
        return "#006d32"
    return "#26a641"


def render_svg(detections: List[Detection]) -> str:
    counts = map_detections(detections)
    cols = list(TACTICS.items())
    width = len(cols) * (_COL_W + _GAP)
    max_rows = max(len(t) for _, t in cols)
    height = _HEAD + max_rows * (_CELL_H + _GAP)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
             f'viewBox="0 0 {width} {height}" font-family="system-ui,sans-serif">']
    parts.append(f'<rect width="{width}" height="{height}" fill="#0d1117"/>')
    for ci, (tactic, techs) in enumerate(cols):
        x = ci * (_COL_W + _GAP)
        parts.append(f'<text x="{x+_COL_W/2}" y="20" fill="#9aa4b2" font-size="10" '
                     f'text-anchor="middle">{_esc(tactic)}</text>')
        for ri, t in enumerate(techs):
            y = _HEAD + ri * (_CELL_H + _GAP)
            c = counts.get(t.id, 0)
            parts.append(f'<rect x="{x}" y="{y}" width="{_COL_W}" height="{_CELL_H}" rx="4" '
                         f'fill="{_color(c)}"><title>{t.id} {_esc(t.name)}: {c} detection(s)</title></rect>')
            parts.append(f'<text x="{x+6}" y="{y+19}" fill="#c9d1d9" font-size="10">{t.id} {_esc(t.name[:16])}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
