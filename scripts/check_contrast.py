#!/usr/bin/env python3
"""Measure the site theme's colour contrast and fail when a pair the site uses drops below
WCAG 2.x AA.

index.html defines every colour as a --tsw-* custom property, once for the dark theme
(`:root, :root[data-theme="dark"]`) and once for the light theme
(`:root[data-theme="light"]`). PAIRS below lists each text/background (and focus/accent)
combination the stylesheet uses, with where it is used and the minimum ratio it needs:
4.5:1 for text, 3:1 for non-text indicators such as the focus ring and accent rules
(WCAG 2.2 success criteria 1.4.3 and 1.4.11). A translucent background is composited
over the surface it sits on; a gradient background is checked at each of its colour stops
and the lowest ratio counts.

Usage:
    python scripts/check_contrast.py            # table of every pair in both themes; exit 1 on a failure
    python scripts/check_contrast.py --markdown # the same table as Markdown (for a PR body)
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import read_text  # noqa: E402

TEXT, UI = 4.5, 3.0

# (foreground token, background token or (translucent token, base token), minimum, where)
PAIRS = [
    ("--tsw-text", "--tsw-bg", TEXT, "body text"),
    ("--tsw-text", "--tsw-surface", TEXT, "text on cards, kbd, theme button"),
    ("--tsw-text", ("--tsw-tint-strong", "--tsw-bg"), TEXT, "blockquote text"),
    ("--tsw-text", ("--tsw-row-alt", "--tsw-bg"), TEXT, "table text, striped row"),
    ("--tsw-text", ("--tsw-row-hover", "--tsw-bg"), TEXT, "table text, hovered row"),
    ("--tsw-text", "--tsw-bg-alt", TEXT, "framework ID chips"),
    ("--tsw-heading", "--tsw-bg", TEXT, "page headings"),
    ("--tsw-heading", "--tsw-surface", TEXT, "card titles, counts"),
    ("--tsw-heading", "--tsw-surface-2", TEXT, "table header cells"),
    ("--tsw-heading", ("--tsw-tint", "--tsw-sidebar-bg"), TEXT, "sidebar site name"),
    ("--tsw-text-muted", "--tsw-bg", TEXT, "lead text, cover tagline"),
    ("--tsw-text-muted", "--tsw-surface", TEXT, "card descriptions"),
    ("--tsw-text-muted", "--tsw-surface-2", TEXT, "time and level pills"),
    ("--tsw-text-muted", "--tsw-sidebar-bg", TEXT, "sidebar links"),
    ("--tsw-text-muted", ("--tsw-nav-bg", "--tsw-bg"), TEXT, "navbar links"),
    ("--tsw-text-muted", "--tsw-cover-bg", TEXT, "cover tagline"),
    ("--tsw-text-dim", "--tsw-bg", TEXT, "footer notice, chain arrows"),
    ("--tsw-text-dim", "--tsw-surface", TEXT, "card labels, search placeholder"),
    ("--tsw-text-dim", "--tsw-sidebar-bg", TEXT, "sidebar section labels"),
    ("--tsw-link", "--tsw-bg", TEXT, "links"),
    ("--tsw-link", "--tsw-surface", TEXT, "links on cards"),
    ("--tsw-link", ("--tsw-tint-strong", "--tsw-bg"), TEXT, "links in blockquotes"),
    ("--tsw-link", "--tsw-sidebar-bg", TEXT, "sidebar link, hovered"),
    ("--tsw-link", ("--tsw-nav-bg", "--tsw-bg"), TEXT, "navbar link, hovered"),
    ("--tsw-link-hover", "--tsw-bg", TEXT, "hovered links"),
    ("--tsw-green", "--tsw-sidebar-bg", TEXT, "sidebar: current page"),
    ("--tsw-green", "--tsw-bg-alt", TEXT, "framework IDs in the Explore chips"),
    ("--tsw-red-text", "--tsw-sidebar-bg", TEXT, "search: matched keyword"),
    ("--tsw-red-text", "--tsw-bg", TEXT, "red text"),
    ("--tsw-cover-title", "--tsw-cover-bg", TEXT, "cover title"),
    ("--tsw-btn-fg", "--tsw-btn-bg", TEXT, "primary buttons"),
    ("--tsw-btn-fg", "--tsw-btn-bg-hover", TEXT, "primary buttons, hovered"),
    ("--tsw-code-fg", "--tsw-code-bg", TEXT, "inline code"),
    ("--tsw-pre-fg", "--tsw-pre-bg", TEXT, "code blocks"),
    ("--tsw-tok-comment", "--tsw-pre-bg", TEXT, "code: comments"),
    ("--tsw-tok-keyword", "--tsw-pre-bg", TEXT, "code: keywords"),
    ("--tsw-tok-string", "--tsw-pre-bg", TEXT, "code: strings"),
    ("--tsw-tok-number", "--tsw-pre-bg", TEXT, "code: numbers"),
    ("--tsw-tok-function", "--tsw-pre-bg", TEXT, "code: functions"),
    ("--tsw-tok-tag", "--tsw-pre-bg", TEXT, "code: tags, properties"),
    ("--tsw-tok-operator", "--tsw-pre-bg", TEXT, "code: operators"),
    ("--tsw-focus", "--tsw-bg", UI, "focus ring"),
    ("--tsw-focus", "--tsw-surface", UI, "focus ring on cards"),
    ("--tsw-red", "--tsw-bg", UI, "red accent rules (door, navbar)"),
    ("--tsw-green", "--tsw-surface", UI, "green accent rule (door)"),
    ("--tsw-link", "--tsw-surface", UI, "blue accent rule (door)"),
]

BLOCKS = {
    "dark": re.compile(r':root,\s*:root\[data-theme="dark"\]\s*\{(.*?)\n\s*\}', re.S),
    "light": re.compile(r':root\[data-theme="light"\]\s*\{(.*?)\n\s*\}', re.S),
}
DECL_RE = re.compile(r"(--tsw-[\w-]+)\s*:\s*([^;]+);")
HEX_RE = re.compile(r"#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b")
RGBA_RE = re.compile(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)")


def tokens(css: str) -> dict[str, dict[str, str]]:
    out = {}
    for theme, rx in BLOCKS.items():
        m = rx.search(css)
        if not m:
            raise SystemExit(f"index.html: no {theme} token block")
        out[theme] = {k: re.sub(r"/\*.*?\*/", "", v).strip() for k, v in DECL_RE.findall(m.group(1))}
    merged = dict(out["dark"])
    merged.update(out["light"])          # the light block overrides the dark one
    out["light"] = merged
    return out


def resolve(toks: dict, name: str) -> str:
    v = toks[name]
    for _ in range(10):
        m = re.fullmatch(r"var\((--tsw-[\w-]+)\)", v)
        if not m:
            return v
        v = toks[m.group(1)]
    return v


def colours(value: str) -> list[tuple[float, float, float, float]]:
    """Every colour in a value (one for a plain colour, each stop for a gradient)."""
    found = []
    for m in re.finditer(HEX_RE.pattern + "|" + RGBA_RE.pattern, value):
        s = m.group(0)
        if s.startswith("#"):
            h = s[1:]
            if len(h) == 3:
                h = "".join(c * 2 for c in h)
            found.append((int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0))
        else:
            r = RGBA_RE.match(s)
            found.append((float(r.group(1)), float(r.group(2)), float(r.group(3)),
                          float(r.group(4)) if r.group(4) else 1.0))
    if not found:
        raise SystemExit(f"no colour in {value!r}")
    return found


def over(top, base):
    a = top[3]
    return tuple(top[i] * a + base[i] * (1 - a) for i in range(3)) + (1.0,)


def luminance(c) -> float:
    def ch(v):
        v /= 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * ch(c[0]) + 0.7152 * ch(c[1]) + 0.0722 * ch(c[2])


def ratio(a, b) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def hexs(c) -> str:
    return "#" + "".join(f"{round(v):02x}" for v in c[:3])


def measure(toks):
    rows = []
    for fg_name, bg_spec, need, where in PAIRS:
        if isinstance(bg_spec, tuple):
            top_name, base_name = bg_spec
            bases = [over(t, b) for t in colours(resolve(toks, top_name)) for b in colours(resolve(toks, base_name))]
            bg_label = f"{top_name} over {base_name}"
        else:
            bases = [b if b[3] == 1 else over(b, colours(resolve(toks, "--tsw-bg"))[0]) for b in colours(resolve(toks, bg_spec))]
            bg_label = bg_spec
        fg = colours(resolve(toks, fg_name))[0]
        worst = min(((ratio(fg if fg[3] == 1 else over(fg, b), b), b) for b in bases), key=lambda x: x[0])
        rows.append((where, fg_name, hexs(fg), bg_label, hexs(worst[1]), worst[0], need))
    return rows


def main() -> int:
    css = read_text("index.html") or ""
    themes = tokens(css)
    md = "--markdown" in sys.argv
    failures = 0
    for theme in ("dark", "light"):
        rows = measure(themes[theme])
        if md:
            print(f"\n{theme.capitalize()} theme\n")
            print("| Used for | Foreground | Background | Ratio | Needs |")
            print("|---|---|---|---:|---:|")
        else:
            print(f"== {theme} theme ==")
        for where, fg_name, fg, bg_label, bg, r, need in rows:
            ok = r >= need
            failures += not ok
            if md:
                print(f"| {where} | `{fg_name}` {fg} | `{bg_label}` {bg} | {r:.2f}:1 | {need}:1{'' if ok else ' FAIL'} |")
            else:
                print(f"  {'ok  ' if ok else 'FAIL'} {r:6.2f}:1 (needs {need}) {fg} on {bg}  {where}")
    if failures:
        print(f"FAIL: {failures} colour pair(s) below WCAG AA")
        return 1
    if not md:
        print(f"OK: all {2 * len(PAIRS)} colour pairs meet WCAG AA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
