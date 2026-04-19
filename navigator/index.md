# ATT&CK Navigator — TeamStarWolf Coverage Layers

Live ATT&CK Enterprise heatmaps showing vendor and pipeline stage coverage across ATT&CK techniques. All layers are sourced from the [TeamStarWolf edge tables](../data/) and [CTID NIST 800-53 R5 mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings).

---

## Full Stack Coverage

| Layer | Description | Load |
|---|---|---|
| [NIST 800-53 R5 Overview](teamstarwolf_vendor_coverage.json) | 313 ATT&CK techniques scored by NIST 800-53 R5 control depth (CTID-sourced mapping) | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json) |

---

## Pipeline Stage Layers

| Layer | Description | Techniques | Load |
|---|---|---|---|
| [Stage 1 — Governance & GRC](stages/stage1_governance_grc.json) | Supply chain controls, vendor risk, policy enforcement | 20 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage1_governance_grc.json) |
| [Stage 2 — Network & Perimeter Security](stages/stage2_network_perimeter.json) | NGFW, IDS/IPS, NDR, DNS security, exfiltration controls | 25 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage2_network_perimeter.json) |
| [Stage 3 — Endpoint & Workload](stages/stage3_endpoint_workload.json) | EDR, HIPS, application control, OS hardening | 25 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage3_endpoint_workload.json) |
| [Stage 4 — Identity & Access Management](stages/stage4_identity_access.json) | IAM, PAM, MFA, SSO, Conditional Access, JIT access | 31 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage4_identity_access.json) |
| [Stage 5 — Application Security](stages/stage5_application_security.json) | SAST, DAST, WAF, API security, DevSecOps pipeline | 27 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage5_application_security.json) |
| [Stage 6 — Data & Cloud Security](stages/stage6_data_cloud.json) | DSPM, CASB, DLP, cloud security posture, data controls | 20 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage6_data_cloud.json) |

---

## Vendor Layers

| Layer | Vendors | Techniques | Load |
|---|---|---|---|
| [SIEM & Detection](vendors/siem_splunk_sentinel_elastic.json) | Splunk ES, Microsoft Sentinel, Elastic Security | 31 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/siem_splunk_sentinel_elastic.json) |
| [EDR & Endpoint](vendors/edr_crowdstrike_sentinelone.json) | CrowdStrike Falcon, SentinelOne, VMware Carbon Black | 25 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/edr_crowdstrike_sentinelone.json) |
| [Cloud Security](vendors/cloud_wiz_prisma_defender.json) | Wiz, Prisma Cloud, Microsoft Defender for Cloud | 25 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/cloud_wiz_prisma_defender.json) |
| [Identity & PAM](vendors/identity_okta_entra_cyberark.json) | Okta, Microsoft Entra ID, CyberArk PAM | 24 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/identity_okta_entra_cyberark.json) |
| [Network Security](vendors/network_paloalto_fortinet.json) | Palo Alto NGFW, Fortinet FortiGate, Cisco Secure | 24 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/network_paloalto_fortinet.json) |
| [WAF & API Protection](vendors/waf_cloudflare_akamai_awswaf.json) | Cloudflare WAF, Akamai, AWS WAF, F5 Advanced | 24 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/waf_cloudflare_akamai_awswaf.json) |
| [Email Security](vendors/email_proofpoint_mimecast_defender.json) | Proofpoint, Mimecast, Microsoft Defender for Office 365 | 24 | [↗ Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/vendors/email_proofpoint_mimecast_defender.json) |

---

## Score Interpretation (Full Stack Layer)

| Score Range | Meaning |
|---|---|
| 20–33 | Many NIST 800-53 controls address this technique; broad vendor coverage across the enterprise stack |
| 10–19 | Moderate control coverage; most mature security programs address this technique |
| 1–9 | Fewer controls map here; may represent a capability gap worth prioritizing |

---

## References

- [Layer JSON source files](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/)
- [Vendor → Control edge table](../data/vendor_to_control.jsonl)
- [Control → Technique edge table](../data/control_to_technique.jsonl)
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
