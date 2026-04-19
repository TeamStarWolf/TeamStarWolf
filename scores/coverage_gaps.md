# Coverage Gap Analysis — TeamStarWolf Vendor Stack

**Generated:** 2026-04-18
**Stack:** CrowdStrike Falcon, SentinelOne, Microsoft Entra ID, Okta, CyberArk, Zscaler, Palo Alto NGFW, Tenable, Qualys, Wiz, Splunk ES, Microsoft Sentinel, Proofpoint, Mimecast, Recorded Future, Mandiant Advantage

This analysis maps the current vendor stack against ATT&CK Enterprise v13 tactics and identifies coverage gaps by tactic. Coverage scores are based on the [`data/vendor_to_technique.jsonl`](../data/vendor_to_technique.jsonl) derived edge table. NIST depth scores are sourced from [CTID NIST 800-53 R5 mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings).

To recompute: `python scripts/compute_coverage.py`

---

## Tactic Coverage Summary

| Tactic | Covered | ATT&CK Total | Coverage % | Status |
|---|---|---|---|---|
| Initial Access | 2 (T1190, T1566) | 9 | **22%** | Partial |
| Execution | 1 (T1059) | 14 | **7%** | Gap |
| Persistence | 4 (T1098, T1136, T1547, T1543) | 19 | **21%** | Partial |
| Privilege Escalation | 3 (T1068, T1078.003, T1558) | 13 | **23%** | Partial |
| Defense Evasion | 2 (T1562, T1040) | 42 | **5%** | Critical Gap |
| Credential Access | 5 (T1003, T1110, T1556, T1621, T1558) | 17 | **29%** | Partial |
| Discovery | 1 (T1046) | 31 | **3%** | Critical Gap |
| Lateral Movement | 2 (T1021, T1534) | 9 | **22%** | Partial |
| Collection | 1 (T1114) | 17 | **6%** | Critical Gap |
| Command & Control | 4 (T1071, T1090, T1095, T1572) | 16 | **25%** | Partial |
| Exfiltration | 3 (T1048, T1041, T1537) | 9 | **33%** | Partial |
| Impact | 3 (T1486, T1490, T1489) | 14 | **21%** | Partial |

**Overall stack coverage: ~25 unique technique/subtechnique IDs across the full ATT&CK Enterprise matrix**

---

## Critical Gaps (Require Capability Addition)

### 1. Collection — 6% Coverage

**What's missing:** Attackers staging and collecting data before exfiltration is nearly invisible to the current stack.

| Uncovered Technique | NIST Depth | Why It Matters |
|---|---|---|
| T1213 — Data from Information Repositories | 24 | Confluence, SharePoint, O365 data harvesting — extremely common in breaches |
| T1530 — Data from Cloud Storage | 33 | S3/Azure Blob/GCS unauthorized data access — highest NIST score in the matrix |
| T1560 — Archive Collected Data | 5 | Pre-exfil staging; zip/rar of sensitive files before sending out |
| T1056 — Input Capture | — | Keylogging and credential capture from interactive sessions |
| T1074 — Data Staged | — | Local/remote staging before exfiltration |
| T1114 — Email Collection | 14 | Mailbox rule creation for auto-forwarding (partial via Mimecast) |

**Recommended addition:** CASB (Netskope, Microsoft Purview, Zscaler CASB) + DLP (Microsoft Purview DLP, Forcepoint)

---

### 2. Discovery — 3% Coverage

**What's missing:** Attackers mapping the environment post-compromise are nearly undetectable with current tooling alone.

| Uncovered Technique | NIST Depth | Why It Matters |
|---|---|---|
| T1082 — System Information Discovery | — | Near-universal in all attacks; precedes targeting decisions |
| T1083 — File and Directory Discovery | — | Attacker locating sensitive files and credentials |
| T1087 — Account Discovery | 3 | Mapping users and groups; precedes privilege escalation |
| T1018 — Remote System Discovery | — | Network mapping post-compromise |
| T1069 — Permission Groups Discovery | — | AD/Azure group enumeration before lateral movement |
| T1482 — Domain Trust Discovery | 9 | Forest/trust enumeration before cross-domain attacks |
| T1580 — Cloud Infrastructure Discovery | 5 | Cloud asset enumeration (partial via Wiz identify) |

**Recommended addition:** UEBA behavioral analytics in existing SIEM (Splunk UBA, Sentinel UEBA, Securonix) — uses existing log telemetry to detect discovery patterns without new data sources.

---

### 3. Defense Evasion — 5% Coverage

**What's missing:** Attackers evading detection is the highest-volume tactic in ATT&CK with 42 techniques, and 95% of it is uncovered.

| Uncovered Technique | NIST Depth | Why It Matters |
|---|---|---|
| T1218 — System Binary Proxy Execution (LOLBAS) | 18 | Living-off-the-land via signed Microsoft binaries; extremely common |
| T1562 — Impair Defenses | 16 | Disabling AV/EDR; log tampering; security tool bypass |
| T1027 — Obfuscated Files or Information | 6 | PowerShell obfuscation, encoded commands |
| T1574 — Hijack Execution Flow | 19 | DLL hijacking, path interception — broad technique family |
| T1036 — Masquerading | 12 | Renaming tools, fake parent processes |
| T1070 — Indicator Removal | 21 | Log clearing, timestomping, artifact deletion |
| T1553 — Subvert Trust Controls | 19 | Code signing bypass, SIP tampering |

**Recommended addition:** Application Control (CrowdStrike App Control, Carbon Black App Control) + CIS Benchmark hardening enforcement (Tanium, Ansible, Puppet) to limit LOLBin abuse and reduce attack surface.

---

### 4. Execution — 7% Coverage

**What's missing:** Only scripting (T1059) is covered. Most execution techniques fall through.

| Uncovered Technique | NIST Depth | Why It Matters |
|---|---|---|
| T1047 — Windows Management Instrumentation | 18 | WMI used heavily by APTs for fileless execution |
| T1053 — Scheduled Task/Job | 15 | Used for both execution and persistence |
| T1106 — Native API | 7 | Direct API calls bypassing scripting detection |
| T1129 — Shared Modules | 5 | DLL loading for execution |
| T1204 — User Execution | 13 | Partial via email security; endpoint detection needed |

**Recommended addition:** EDR policy tuning — CrowdStrike/SentinelOne already deployed, expand behavioral rules to cover WMI execution and scheduled task abuse. Existing telemetry is present; rule coverage is the gap.

---

## Priority Recommendations

| Priority | Capability | Fills Gap | Effort | Vendor Examples |
|---|---|---|---|---|
| **P1** | CASB + DLP | Collection, Exfiltration | Medium | Netskope, Microsoft Purview, Zscaler CASB |
| **P1** | UEBA Tuning | Discovery, Credential Access | Low | Splunk UBA (already have Splunk), Sentinel UEBA |
| **P2** | Application Control | Defense Evasion, Execution | Medium | CrowdStrike App Control, Carbon Black |
| **P2** | NDR Enhancement | C2, Lateral Movement | Medium | Corelight, ExtraHop (already deployed) |
| **P3** | Deception / Honeypots | Discovery, Lateral Movement | Low | Attivo (SentinelOne), Illusive Networks |
| **P3** | Cloud DSPM | Collection (cloud) | Medium | Wiz DSPM, Varonis, BigID |

---

## How to Use This Analysis

1. Load the [TeamStarWolf Navigator layers](../navigator/) to visualize coverage visually
2. Run `python scripts/compute_coverage.py` to recompute with updated edge tables
3. Use the P1 recommendations to build the business case for capability additions
4. As new vendors are added to `data/vendor_to_control.jsonl`, rerun to see coverage improvement
5. Cross-reference with [CONTROLS_MAPPING.md](../CONTROLS_MAPPING.md) to identify which NIST controls the gap vendors would satisfy

---

## References

- [Vendor to Control edges](../data/vendor_to_control.jsonl)
- [Control to Technique edges](../data/control_to_technique.jsonl)
- [Vendor to Technique derived edges](../data/vendor_to_technique.jsonl)
- [CTID NIST 800-53 R5 mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings)
- [ATT&CK Navigator layers](../navigator/)
- [Coverage Schema](../COVERAGE_SCHEMA.md)
