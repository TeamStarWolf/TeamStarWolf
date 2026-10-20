<!-- explore:start (written by scripts/build_explore.py from data/; do not edit) -->

# Explore the frameworks

> Every framework object that has a page in this library, in one table: filter it by kind, tactic, platform, software type or CAPEC severity, or type an ID, a name or an alias (T1059, APT29, Cozy Bear, CAPEC-66) to find one.

<div id="tsw-explore" class="tsw-explore-app"></div>

## Browse by family

The same 2,914 objects, one index page per family. The table above is built from the JSONL files in [data/](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) into [assets/explore.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/assets/explore.json).

| Family | Objects | Index | Built from |
|---|---|---|---|
| ATT&CK techniques | 714 (17 revoked or deprecated in v19.2, kept for reference) | [ATT&CK techniques](/mitre/techniques/README.md) | `data/attack/technique_profiles.jsonl` |
| ATT&CK groups | 176 | [ATT&CK groups](/mitre/groups/README.md) | `data/attack/group_profiles.jsonl` |
| ATT&CK software | 825 | [ATT&CK software](/mitre/software/README.md) | `data/attack/software_profiles.jsonl` |
| ATT&CK campaigns | 56 | [ATT&CK campaigns](/mitre/campaigns/README.md) | `data/attack/campaign_profiles.jsonl` |
| ATT&CK mitigations | 44 | [ATT&CK mitigations](/mitre/mitigations/README.md) | `data/attack/mitigations.jsonl` |
| CAPEC attack patterns | 615 (57 deprecated or obsolete upstream) | [CAPEC attack patterns](/mitre/capec/README.md) | `data/weaknesses/capec.jsonl` |
| D3FEND countermeasures | 156 | [D3FEND countermeasures](/mitre/d3fend/README.md) | `data/attack/d3fend_countermeasures.jsonl` |
| ATLAS techniques | 170 | [ATLAS techniques](/mitre/atlas/README.md) | `data/ai/atlas_techniques.jsonl` |
| ATLAS mitigations | 35 | [ATLAS mitigations](/mitre/atlas/README.md) | `data/ai/atlas_mitigations.jsonl` |
| F3 techniques | 123 | [F3 techniques](/mitre/f3/README.md) | `data/fraud/f3_techniques.jsonl` |

Versions: ATT&CK v19.2 (Enterprise), CAPEC 3.9. The licenses and notices for each framework are in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md); how the data is built and checked is in [About the data](/ABOUT_THE_DATA.md).

ATT&CK&reg; and MITRE ATT&CK&reg; are registered trademarks of The MITRE Corporation. CAPEC, D3FEND and ATLAS are maintained by The MITRE Corporation, and F3 by MITRE's Center for Threat-Informed Defense. This project is not affiliated with or endorsed by MITRE.

<!-- explore:end -->
