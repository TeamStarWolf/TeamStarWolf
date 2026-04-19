# ATT&CK Navigator — TeamStarWolf Coverage Layers

Live ATT&CK Enterprise heatmaps showing vendor and pipeline stage coverage across ATT&CK techniques. All layers are sourced from the [TeamStarWolf edge tables](../data/) and [CTID NIST 580-53 R5 mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings).

---

## Available Layers

### Full Stack Coverage
| Layer | Description | Load |
|---|---|---|
| [NIST 800-53 R5 Overview](teamstarwolf_vendor_coverage.json) | 313 techniques scored by NIST 800-53 control depth (CTID-sourced) | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json) |

### Vendor Layers
| Layer | Vendors | Primary Focus | Load |
|---|---|---|---|
| [EDR](vendors/edr_crowdstrike_sentinelone.json) | CrowdStrike Falcon, SentinelOne | Endpoint prevent/detect | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/edr_crowdstrike_sentinelone.json) |
| Network Security — Palo Alto NGFW / Fortinet / Cisco | 24 techniques: C2 protocol detection, DNS tunneling, exfiltration blocking | [Download JSON](vendors/network_paloalto_fortinet.json) |
| Identity — Okta / Entra ID / CyberArk PAM | 24 techniques: brute force, pass-the-hash, Kerberoasting, privilege escalation | [Download JSON](vendors/identity_okta_entra_cyberark.json) |
| [Identity & PAM](vendors/identity_entra_okta_cyberark.json) | Microsoft Entra ID, Okta, CyberArk | Credential & access protection | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/identity_entra_okta_cyberark.json) |
| [Network & Zero Trust](vendors/network_zscaler_paloalto.json) | Zscaler, Palo Alto NGFW | Boundary & C2 prevention | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/network_zscaler_paloalto.json) |
| [Email Security](vendors/email_proofpoint_mimecast.json) | Proofpoint, Mimecast | Phishing prevention | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/email_proofpoint_mimecast.json) |
| [Vulnerability Management](vendors/vuln_mgmt_tenable_qualys_wiz.json) | Tenable, Qualys, Wiz | Pre-compromise identify | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/vuln_mgmt_tenable_qualys_wiz.json) |
| [SIEM](vendors/siem_splunk_sentinel_elastic.json) | Splunk ES, Microsoft Sentinel, Elastic SIEM | Log correlation, behavioral detection, UEBA | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/siem_splunk_sentinel_elastic.json) |
| [Cloud Security](vendors/cloud_wiz_prisma_defender.json) | Wiz, Prisma Cloud, Microsoft Defender for Cloud | CSPM, secrets scanning, cloud account protection | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/cloud_wiz_prisma_defender.json) |

### Pipeline Stage Layers
| Layer | Stage | NIST Controls | Load |
|---|---|---|---|
| [Stage 1 — Governance & GRC](stages/stage1_governance_grc.json) | Governance, Risk & Compliance | PL-1, RA-3, CA-2, CA-7, PM-9, PM-30 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage1_governance_grc.json) |
| [Stage 2 — Network & Perimeter Security](stages/stage2_network_perimeter.json) | NGFW, IDS/IPS, NDR, DNS security, network segmentation | [Download JSON](stages/stage2_network_perimeter.json) |
| [Stage 2 — Identity & Access](stages/stage2_identity_access.json) | Identity & Access Management | IA-2, IA-5, AC-2, AC-3, AC-6 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage2_identity_access.json) |
| [Stage 3 — Endpoint & Workload](stages/stage3_endpoint_workload.json) | Endpoint & Workload Protection | SI-3, SI-7, CM-7, CM-8, SC-3, SC-39 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage3_endpoint_workload.json) |
| [Stage 4 — Identity & Access Management](stages/stage4_identity_access.json) | IAM, PAM, MFA, SSO, Conditional Access, JIT access controls | [Download JSON](stages/stage4_identity_access.json) |
| [Stage 5 — Application Security](stages/stage5_application_security.json) | SAST, DAST, SCA, WAF, API security, DevSecOps pipeline controls | [Download JSON](stages/stage5_application_security.json) |
| [Stage 4 — Network & Boundary](stages/stage4_network_boundary.json) | Network & Boundary Defense | SC-7, SC-8, AC-17, AC-20, SI-8, SC-5 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage4_network_boundary.json) |
| [Stage 5 — Visibility & Detection](stages/stage5_visibility_detection.json) | Visibility, Detection & Operations | AU-2, AU-6, IR-4, IR-5, SI-4, RA-5 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage5_visibility_detection.json) |
| [Stage 6 — Data & Cloud](stages/stage6_data_cloud.json) | Data & Cloud Security | MP-2, SC-28, SC-8, RA-5, CM-6, SA-9 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage6_data_cloud.json) |

---

## Score Interpretation (Full Stack Layer)

- **High score (20–33)** — Many NIST 800-53 controls address this technique; broad vendor coverage across the enterprise stack
- **Medium score (10–19)** — Moderate control coverage; most mature security programs address this
- **Low score (1–9)** — Fewer controls map here; may represent capability gaps worth prioritizing

---

## References

- [Layer JSON source files](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/)
- [Vendor → Control edge table](../data/vendor_to_control.jsonl)
- [Control → Technique edge table](../data/control_to_technique.jsonl)
- [Vendor → Technique derived edges](../data/vendor_to_technique.jsonl)
- [Controls Mapping reference](../CONTROLS_MAPPING.md)
- [Coverage gap analysis](../scores/coverage_gaps.md)
- [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/)

---

<div style="position:relative; width:100%; padding-bottom:65%; min-height:500px;">
  <iframe
    src="https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FTeamStarWolf%2FTeamStarWolf%2Fmain%2Fnavigator%2Fteamstarwolf_vendor_coverage.json"
    style="position:absolute; top:0; left:0; width:100%; height:100%; border:1px solid #334155; border-radius:6px;"
    title="MITRE ATT&CK Navigator — TeamStarWolf Full Stack Coverage"
    loading="lazy"
    allowfullscreen>
  </iframe>
</div>
