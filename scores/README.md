# Scores

Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17.

> Computed views over the ATT&CK v19.2 data: how much of the Enterprise matrix a modeled vendor stack reaches through NIST SP 800-53 control mappings, and which techniques are both widely used by tracked groups and thinly covered by controls. Every file here is generated.

## What is here

| File | Contents | Written by |
|---|---|---|
| [coverage_gaps.md](/scores/coverage_gaps.md) | The coverage page: per-tactic coverage, the uncovered techniques, and what "covered" means | `scripts/compute_coverage.py` |
| `coverage_gaps.json` | The same summary, ranked gap list, and recommendations as data | `scripts/compute_coverage.py` |
| `tactic_coverage.json` | Coverage per tactic, with the technique lists | `scripts/compute_coverage.py` |
| `vendor_coverage.json` | Technique coverage per modeled product | `scripts/compute_coverage.py` |
| [attack_priority_gaps.md](/scores/attack_priority_gaps.md) | Techniques ranked by tracked-group usage weighted by thin NIST control coverage, and coverage by tactic | `scripts/build_priority_gaps.py` |
| `attack_priority_gaps.json` | The ranked list and per-tactic figures as data | `scripts/build_priority_gaps.py` |

`build_priority_gaps.py` also writes the analytics layers in `navigator/analytics/` from the same run.

## How it is generated

Both scripts read only committed data (`data/attack/technique_profiles.jsonl`, `data/attack/superseded_by.jsonl`, the edge tables, and `data/vendor_to_technique.jsonl`), use only the Python standard library, and produce byte-identical output for the same inputs. Each page records the SHA-256 prefix of every input it was built from.

```
python scripts/compute_coverage.py       # rewrites the coverage files
python scripts/build_priority_gaps.py    # rewrites the priority-gap page, its JSON, and the analytics layers
```

The Validate Data Files workflow runs both with `--check` and fails if a committed file is stale. Do not edit these files by hand; change the data or the script.

## How to use it

- Read "covered" as defined on each page. On [coverage_gaps.md](/scores/coverage_gaps.md), a technique is covered when at least one modeled product satisfies a NIST control that the CTID mapping links to it. That is a statement about mappings, not about a deployed, tuned, or tested defense.
- The vendor-to-control mappings behind the coverage page are this library's editorial assessments ([CONTROLS_MAPPING.md](/CONTROLS_MAPPING.md)); treat the result as a starting point for your own assessment.
- Use the priority list to choose where to look next, then confirm with your own telemetry and the [detection strategies](/detections/strategies/README.md). The [Run a coverage gap assessment](/guides/RUN_A_COVERAGE_GAP_ASSESSMENT.md) guide walks through that workflow.
- Load the JSON files directly, or open the matching layers from [navigator/index.md](/navigator/index.md) in the ATT&CK Navigator.
