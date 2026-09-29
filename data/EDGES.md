# Edge Contract

The **normalized relationship contract** for the TeamStarWolf library. Every derived
"edge" dataset (a row that asserts a relationship between two entities) is listed
here with its normalized interpretation: which field is the **source** node, which is
the **target**, the node **types**, the **edge type**, and the row **cardinality**.

This is the contract a consumer — e.g. ATTACK-Navi's cross-framework graph — uses to
join the library's relationships without re-deriving them. The source/target field
presence declared here is enforced in CI by `scripts/validate_jsonl.py` (the
`edge-contract` check): every row must carry a non-empty source id and a non-empty
target id (or, for adjacency rows, a non-empty target list whose items carry the
declared id key). See [VOCABULARIES.md](VOCABULARIES.md) for the allowed
`edge_type` / `confidence` / `relation` value sets and [MANIFEST.json](MANIFEST.json)
for per-file provenance, row counts and hashes.

Node id conventions: `technique` = ATT&CK `T####[.###]` (Enterprise/Mobile) or ICS
`T0###`/`T16##.###`; `mitigation` = `M####`; `group` = `G####`; `software` =
`S####`; `control` = NIST 800-53 id (e.g. `AC-2`); `d3fend_countermeasure` = a
D3FEND technique name; `car_analytic` = `CAR-YYYY-MM-NNN`; `engage_activity` =
`EAC####`; `vendor` = normalized vendor name.

## Flat edges (one row = one source → one target)

| Dataset | Source (field · type) | Target (field · type) | Edge type | Confidence | Provenance |
|---|---|---|---|---|---|
| `control_to_technique.jsonl` | `nist_control` · control | `attack_technique` · technique | `control_mitigates_technique` | `confidence` | CTID (NIST 800-53 r5) |
| `vendor_to_control.jsonl` | `vendor_normalized` · vendor | `nist_control` · control | `vendor_satisfies_control` | `confidence` | TeamStarWolf |
| `vendor_to_technique.jsonl` | `vendor_normalized` · vendor | `attack_technique` · technique | `vendor_covers_technique` | `confidence` | TeamStarWolf ⋈ CTID |
| `attack/mitigation_to_technique.jsonl` | `mitigation_id` · mitigation | `technique_id` · technique | `mitigation_mitigates_technique` | — | MITRE ATT&CK |
| `attack/software_to_technique.jsonl` | `software_id` · software | `technique_id` · technique | `software_uses_technique` | — | MITRE ATT&CK |
| `attack/group_to_technique.jsonl` | `group_id` · group | `technique_id` · technique | `group_uses_technique` | — | MITRE ATT&CK |
| `attack/ics/group_to_technique.jsonl` | `group_id` · group | `technique_id` · technique | `group_uses_technique` | — | MITRE ATT&CK (ICS) |
| `attack/mobile/group_to_technique.jsonl` | `group_id` · group | `technique_id` · technique | `group_uses_technique` | — | MITRE ATT&CK (Mobile) |
| `attack/technique_to_d3fend.jsonl` | `technique_id` · technique | `d3fend_technique` · d3fend_countermeasure | `technique_countered_by_d3fend` (see `relation`) | — | MITRE D3FEND |
| `attack/technique_to_d3fend_internal.jsonl` | `technique_id` · d3fend_offensive_technique | `d3fend_technique` · d3fend_countermeasure | `technique_countered_by_d3fend` (see `relation`) | — | MITRE D3FEND |
| `attack/superseded_by.jsonl` | `old_id` · technique | `new_id` · technique¹ | `technique_superseded_by` | — | MITRE ATT&CK |

¹ `new_id` is nullable: a `deprecated` retirement (or a revoked-to-dead-end) has `new_id: null`. See [VOCABULARIES.md](VOCABULARIES.md) `reason`.

## Adjacency edges (one row = one source → a list of targets)

| Dataset | Source (field · type) | Target (field · item id · type) | Edge type | Provenance |
|---|---|---|---|---|
| `engage/attack_to_engage.jsonl` | `technique_id` · technique | `engage_activities[].id` · engage_activity | `technique_countered_by_engage` | MITRE Engage |
| `attack/technique_to_car.jsonl` | `technique_id` · technique | `car[].car_id` · car_analytic | `technique_detected_by_car` | MITRE CAR |

## Node-embedded edges (relationships stored on entity profiles, not as edge rows)

Some relationships live as fields on the entity profiles rather than as standalone
edge rows. They are not covered by the `edge-contract` check (the profiles have their
own primary-key validation) but are part of the same relationship graph:

- `attack/technique_profiles.jsonl` → `capec` (technique → CAPEC ids),
  `nist_800_53_controls` / `nist_800_53_controls_rolled` (technique → controls),
  `mitigations` (technique → mitigations), `d3fend`, `data_components`.
- `attack/{group,software,campaign}_profiles.jsonl` → `techniques` (actor → techniques).

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
