# Data Vocabularies

The controlled vocabularies used by the crosswalk / edge datasets. These are the
allowed value sets a consumer (e.g. ATTACK-Navi's cross-framework graph) can rely
on. Library-defined vocabularies are stable and owned here; MITRE-derived
vocabularies track the upstream framework and are updated when it changes. The
`confidence`, `coverage_type`, `mapping_type`, `edge_type`, `relation`, and
`reason` values below are enforced in CI by `scripts/validate_jsonl.py`; a value
outside the locked set fails the build. See [MANIFEST.json](MANIFEST.json) for
per-file provenance and [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Edge / crosswalk vocabularies (library-defined: locked)

| Field | Files | Allowed values | Meaning |
|---|---|---|---|
| `confidence` | control_to_technique, vendor_to_technique, vendor_to_control | `high`, `medium`, `low` | Mapping confidence. control_to_technique + vendor_to_control are all `high` (direct CTID / authored mappings); vendor_to_technique spans all three (derived join). |
| `edge_type` | control_to_technique / vendor_to_technique / vendor_to_control | `control_mitigates_technique` / `vendor_covers_technique` / `vendor_satisfies_control` | The relationship the row asserts (one value per file). |
| `mapping_type` | control_to_technique | `mitigates` | The CTID mapping relationship. |
| `coverage_type` | vendor_to_technique | `prevent`, `detect`, `respond`, `identify`, `prevent_detect` | How a vendor control covers a technique (NIST CSF-style function; `prevent_detect` = both). |
| `ctid_source` | control_to_technique | `nist800-53-r5` | The CTID Mappings Explorer source dataset. |
| `reason` | superseded_by | `revoked`, `deprecated` | Why an ATT&CK id was retired: `revoked` (replaced by `new_id`; may be null if the replacement is itself a dead-end) vs `deprecated` (removed, `new_id` null). |

> Known gap: `vendor_to_control.pipeline_stage` is present in the schema but empty in every row — populate or drop it in a future pass. Not currently consumed.

## Framework-derived vocabularies (track upstream)

| Field | Files | Allowed values | Source |
|---|---|---|---|
| `relation` | technique_to_d3fend | analyzes, authenticates, blocks, configures, creates, deletes, detects, disables, encrypts, erases, evaluates, filters, hardens, inventories, isolates, limits, manages, maps, may-access, may-contain, modifies, monitors, neutralizes, obfuscates, quarantines, reads, regenerates, restores, restricts, spoofs, strengthens, suspends, terminates, updates, use-limits, uses, validates, verifies | MITRE D3FEND digital-artifact relationships |
| `abstraction` | weaknesses/capec | Meta, Standard, Detailed | MITRE CAPEC |
| `abstraction` | weaknesses/cwe | Pillar, Class, Base, Variant, Compound | MITRE CWE |
| `status` | weaknesses/capec | Draft, Usable, Stable, Obsolete, Deprecated | MITRE CAPEC |
| `status` | weaknesses/cwe | Draft, Incomplete, Stable, Deprecated | MITRE CWE |
| `likelihood` | weaknesses/capec | High, Medium, Low (or empty) | MITRE CAPEC (Likelihood Of Attack) |
| `typical_severity` | weaknesses/capec | Very High, High, Medium, Low, Very Low (or empty) | MITRE CAPEC |

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
