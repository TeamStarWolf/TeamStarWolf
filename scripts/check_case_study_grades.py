#!/usr/bin/env python3
"""Keep the case-study evidence-grade vocabulary closed, and report study length.

The library grades every claim with one of four labels: Confirmed, Reported, Inferred and
Demonstrated. The legend lives in case-studies/README.md under "## Method", and many studies
carry their own "| Grade | Meaning in this study |" table tuned to the sources they opened.
This check fails when:

  * the README Method legend does not define exactly the four canonical grades (so the
    legend cannot silently drift out of step with the prose again), or
  * any study's own grade table defines a label that is not one of the four (a typo, or a
    fifth grade introduced without updating the legend).

It also prints, for information only, every study over a length threshold, so the
oversized studies the critique flagged stay visible. Length never fails the check.

Usage:
    python scripts/check_case_study_grades.py            # report (length + any problems)
    python scripts/check_case_study_grades.py --check    # exit 1 on a vocabulary problem
    python scripts/check_case_study_grades.py --self-test # planted pass/fail cases
"""
import argparse
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CS_DIR = os.path.join(ROOT, "case-studies")

GRADES = ("Confirmed", "Reported", "Inferred", "Demonstrated")
GRADE_SET = set(GRADES)
LONG_WORDS = 4000
SKIP = {"README.md", "TIMELINE.md"}

HEADER_RE = re.compile(r"^\|\s*Grade\s*\|\s*Meaning")
SEP_RE = re.compile(r"^\|[\s:|-]+\|?\s*$")
# first cell of a table row, with optional bold/emphasis around the label
ROW_RE = re.compile(r"^\|\s*\*{0,2}([A-Za-z][A-Za-z ]*?)\*{0,2}\s*\|")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def grade_tables(text: str) -> list[list[str]]:
    """Every '| Grade | Meaning... |' table in the text, as a list of its left-column
    labels (the separator row excluded)."""
    lines = text.split("\n")
    tables, i = [], 0
    while i < len(lines):
        if HEADER_RE.match(lines[i]):
            labels, j = [], i + 1
            if j < len(lines) and SEP_RE.match(lines[j]):
                j += 1
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                m = ROW_RE.match(lines[j])
                if m:
                    labels.append(m.group(1).strip())
                j += 1
            tables.append(labels)
            i = j
        else:
            i += 1
    return tables


def legend_labels(readme_text: str) -> list[str]:
    """The grade labels the README Method legend defines."""
    m = re.search(r"\n## Method\b(.*?)(?:\n## |\Z)", readme_text, re.S)
    section = m.group(1) if m else readme_text
    tabs = grade_tables(section)
    return tabs[0] if tabs else []


def scan() -> tuple[list[str], list[tuple[int, str]]]:
    """Return (problems, long_studies). problems is empty when the vocabulary is closed."""
    problems: list[str] = []

    readme = os.path.join(CS_DIR, "README.md")
    legend = legend_labels(read(readme))
    if set(legend) != GRADE_SET:
        problems.append(
            f"README.md: the Method legend defines {legend or 'no grades'}; "
            f"it must define exactly {list(GRADES)}"
        )

    longs: list[tuple[int, str]] = []
    for path in sorted(glob.glob(os.path.join(CS_DIR, "*.md"))):
        base = os.path.basename(path)
        if base in SKIP:
            continue
        text = read(path)
        for labels in grade_tables(text):
            extra = sorted({l for l in labels if l not in GRADE_SET})
            if extra:
                problems.append(f"{base}: grade table defines non-canonical label(s): {extra}")
        words = len(text.split())
        if words > LONG_WORDS:
            longs.append((words, base))
    return problems, sorted(longs, reverse=True)


def self_test() -> None:
    ok_readme = "\n## Method\n\n| Grade | Meaning |\n|---|---|\n" + \
        "".join(f"| {g} | x |\n" for g in GRADES) + "\n## Next\n"
    assert set(legend_labels(ok_readme)) == GRADE_SET, "legend should read all four grades"

    short_readme = "\n## Method\n\n| Grade | Meaning |\n|---|---|\n| Confirmed | x |\n| Reported | x |\n| Demonstrated | x |\n\n## Next\n"
    assert set(legend_labels(short_readme)) != GRADE_SET, "three-grade legend must not match"

    study_ok = "| Grade | Meaning in this study |\n|---|---|\n| Confirmed | x |\n| **Inferred** | y |\n\ntext"
    assert all(l in GRADE_SET for t in grade_tables(study_ok) for l in t), "canonical labels pass"

    study_bad = "| Grade | Meaning |\n|---|---|\n| Confirmed | x |\n| Alleged | y |\n\ntext"
    labels = [l for t in grade_tables(study_bad) for l in t]
    assert "Alleged" in labels and "Alleged" not in GRADE_SET, "a fifth grade must be caught"

    no_table = "Some prose with (Confirmed [1]) inline and no grade table at all.\n"
    assert grade_tables(no_table) == [], "inline-only study has no table to check"

    print("self-test: OK (legend closure, per-study table closure, bold labels, no-table case)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 on a vocabulary problem")
    ap.add_argument("--self-test", action="store_true", help="run planted cases and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0

    problems, longs = scan()

    if longs:
        print(f"case-study length (over {LONG_WORDS} words, information only): {len(longs)} studies")
        for words, base in longs[:10]:
            print(f"  {words:>6} words  {base}")
        if len(longs) > 10:
            print(f"  ... and {len(longs) - 10} more")

    if problems:
        print("FAIL: evidence-grade vocabulary")
        for p in problems:
            print(f"  - {p}")
        return 1 if args.check else 0

    print(f"OK: grade vocabulary closed (legend = {list(GRADES)}; every study table uses only these)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
