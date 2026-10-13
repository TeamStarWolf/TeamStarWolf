# Edge Contract

The normalized relationship contract for the TeamStarWolf library. Every derived
"edge" dataset (a row that asserts a relationship between two entities) is listed
here with its normalized interpretation: which field is the source node, which is
the target, the node types, the edge type, and the row cardinality.

This is the contract a consumer (e.g. ATTACK-Navi's cross-framework graph) uses to
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

## Flat edges (one row = one source to one target)

| Dataset | Source (field, type) | Target (field, type) | Edge type | Confidence | Provenance |
|---|---|---|---|---|---|
| `control_to_technique.jsonl` | `nist_control`, control | `attack_technique`, technique | `control_mitigates_technique` | `confidence` | CTID (NIST 800-53 r5) |
| `vendor_to_control.jsonl` | `vendor_normalized`, vendor | `nist_control`, control | `vendor_satisfies_control` | `confidence` | TeamStarWolf |
| `vendor_to_technique.jsonl` | `vendor_normalized`, vendor | `attack_technique`, technique | `vendor_covers_technique` | `confidence` | TeamStarWolf ⋈ CTID |
| `attack/mitigation_to_technique.jsonl` | `mitigation_id`, mitigation | `technique_id`, technique | `mitigation_mitigates_technique` | N/A | MITRE ATT&CK |
| `attack/software_to_technique.jsonl` | `software_id`, software | `technique_id`, technique | `software_uses_technique` | N/A | MITRE ATT&CK |
| `attack/group_to_technique.jsonl` | `group_id`, group | `technique_id`, technique | `group_uses_technique` | N/A | MITRE ATT&CK |
| `attack/ics/group_to_technique.jsonl` | `group_id`, group | `technique_id`, technique | `group_uses_technique` | N/A | MITRE ATT&CK (ICS) |
| `attack/mobile/group_to_technique.jsonl` | `group_id`, group | `technique_id`, technique | `group_uses_technique` | N/A | MITRE ATT&CK (Mobile) |
| `attack/technique_to_d3fend.jsonl` | `technique_id`, technique | `d3fend_technique`, d3fend_countermeasure | `technique_countered_by_d3fend` (see `relation`) | N/A | MITRE D3FEND |
| `attack/technique_to_d3fend_internal.jsonl` | `technique_id`, d3fend_offensive_technique | `d3fend_technique`, d3fend_countermeasure | `technique_countered_by_d3fend` (see `relation`) | N/A | MITRE D3FEND |
| `attack/superseded_by.jsonl` | `old_id`, technique | `new_id`, technique¹ | `technique_superseded_by` | N/A | MITRE ATT&CK |

¹ `new_id` is nullable: a `deprecated` retirement (or a revoked-to-dead-end) has `new_id: null`. See [VOCABULARIES.md](VOCABULARIES.md) `reason`.

## Adjacency edges (one row = one source to a list of targets)

| Dataset | Source (field, type) | Target (field, item id, type) | Edge type | Provenance |
|---|---|---|---|---|
| `engage/attack_to_engage.jsonl` | `technique_id`, technique | `engage_activities[].id`, engage_activity | `technique_countered_by_engage` | MITRE Engage |
| `attack/technique_to_car.jsonl` | `technique_id`, technique | `car[].car_id`, car_analytic | `technique_detected_by_car` | MITRE CAR |

## Node-embedded edges (relationships stored on entity profiles, not as edge rows)

Some relationships live as fields on the entity profiles rather than as standalone
edge rows. They are not covered by the `edge-contract` check (the profiles have their
own primary-key validation) but are part of the same relationship graph:

- `attack/technique_profiles.jsonl` -> `capec` (technique -> CAPEC ids),
  `nist_800_53_controls` / `nist_800_53_controls_rolled` (technique -> controls),
  `mitigations` (technique -> mitigations), `d3fend`, `data_components`.
  `nist_800_53_controls_via_revoked` / `capec_via_revoked` record which of those
  edges were carried forward from a revoked predecessor (see below).
- `attack/{group,software,campaign}_profiles.jsonl` -> `techniques` (actor -> techniques).

Denormalised counts are copies of an edge table, never independent facts. On
`technique_profiles.jsonl`, `group_count`, `software_count`, `campaign_count`,
`mitigations` / `mitigation_count` and `detection_strategies` /
`has_detection_strategy` are re-derived by `scripts/build_attack_core.py` from the
same v19.2 relationships that write `group_to_technique`, `software_to_technique`,
`campaign_profiles.techniques`, `mitigation_to_technique` and
`detection_strategies.jsonl`; so are `technique_count` on `mitigations.jsonl`,
`groups.jsonl`, `software.jsonl` and `campaigns.jsonl`. `scripts/validate_jsonl.py`
(layer 6, count-vs-edge) fails when a stored count or list differs from its edge
table. A technique revoked in v19.2 has none of these ATT&CK relationships of its own
(ATT&CK moved them to the successor), so its counts are 0; the third-party
crosswalks below are what a revoked id keeps.

The ICS and Mobile files (`attack/ics/*`, `attack/mobile/*`) are generated by the same
script from the ICS and Mobile v19.2 bundles, pinned to the same attack-stix-data
commit and SHA-256-checked like the Enterprise one (`data/MANIFEST.json` `inputs`).
Their profile fields `name`, `tactics`, `platforms`, `mitigations` / `mitigation_count`,
`group_count`, `software_count`, `campaign_count` and `has_detection` (an ATT&CK
detection strategy detects the technique), and the `technique_count` /
`software_count` / `group_count` on their groups, software and mitigations, are
re-derived on every run. `attack/superseded_by.jsonl` is derived from the
revoked/deprecated techniques of all three bundles (a revoked id's `new_id` is the live
end of its `revoked-by` chain). `scripts/build_attack_core.py --check` runs in CI and
fails if any of these files drifts from the pinned STIX.

`description` is carried, not derived. No normalisation rule reproduces the committed
text from the STIX (it mixes one-, two- and three-sentence summaries of the first
paragraph, some with citations stripped), so a committed row keeps its `description`
on `attack/technique_profiles.jsonl`, `attack/mitigations.jsonl` and the ICS/Mobile
`technique_profiles`, `groups` and `mitigations` files. Only a row new to a file gets
one, by the fallback rule documented in `scripts/build_attack_core.py`.

## Revoked technique ids, carry-forward and integrity rules

Third-party mappings are published against the ATT&CK version they were authored for:
the CTID NIST 800-53 mapping targets ATT&CK v16.1, CAPEC/D3FEND/CAR/Engage target older
releases. When ATT&CK revokes a technique in favour of another (`revoked-by`, recorded in
`attack/superseded_by.jsonl`, e.g. T1562.001 -> T1685, T1070.001 -> T1685.005), the
mapping still describes the same behaviour, so:

- the source edge rows stay keyed on the id the upstream publishes (the revoked id keeps
  a lineage row in `technique_profiles.jsonl` and keeps its own edges);
- every consumer carries those edges forward to the live successor, following
  `superseded_by` chains, through one shared rule (`scripts/attack_ids.py`):
  `build_control_rollup.py` (profile NIST fields), `backfill_capec_edges.py` (profile
  CAPEC), `build_ctid_edges.py` (`vendor_to_technique.jsonl`) and the D3FEND/CAR/Engage
  loaders of `generate_mitre_pages.py`;
- a carried edge names its predecessor(s) in `via_revoked` (edge rows) or
  `*_via_revoked` ({predecessor: [targets]}, profiles), so the upstream is never
  presented as mapping the new id directly;
- a key that was already stale in the upstream's own version (T1574.002, revoked in
  v16) is re-keyed in `control_to_technique.jsonl` itself, again with `via_revoked`.

`scripts/validate_jsonl.py` enforces, in CI: one row per (source, target) in every edge
table; every ATT&CK technique reference is live in the table's domain or resolves through
`superseded_by` to a live successor (an unknown id, e.g. a Mobile id in an Enterprise
table, fails); `via_revoked` ids resolve to the row's target; and a row's denormalised
`tactics` equals the target technique's current tactics. `build_ctid_edges.py --check`
fails if either CTID-derived table drifts from its sources.

*Last updated: 2026-10-13 | TeamStarWolf Cybersecurity Reference Library*
