# MITRE Cross-Framework Crosswalk

<a id="crosswalk"></a>

[MITRE Hub](/mitre/README.md) · [Techniques](/mitre/techniques/README.md) · [Mitigations](/mitre/mitigations/README.md) · [D3FEND](/mitre/d3fend/README.md) · [CAPEC](/mitre/capec/README.md)

The join in one place: **ATT&CK technique ↔ Mitigation (M-code) ↔ NIST 800-53 ↔ D3FEND ↔ CAPEC**. Two views: a per-mitigation rollup (which NIST families and D3FEND countermeasures each mitigation brings), and a per-technique index of counts + links. ATT&CK v19.2.

## Per-mitigation rollup

For each ATT&CK mitigation: how many techniques it addresses, the NIST 800-53 control families most associated with those techniques, and how many distinct D3FEND countermeasures they map to. This is the mitigation ↔ control ↔ D3FEND join not expressed elsewhere.

| Mitigation | Techniques | Top NIST 800-53 families | D3FEND countermeasures |
|---|---:|---|---:|
| [M1018 — User Account Management](/mitre/mitigations/M1018.md) | 120 | AC, CM, SI, IA, SC, CA, SA, RA | 106 |
| [M1026 — Privileged Account Management](/mitre/mitigations/M1026.md) | 112 | AC, CM, SI, IA, SC, SA, CA, RA | 103 |
| [M1047 — Audit](/mitre/mitigations/M1047.md) | 109 | AC, CM, SI, IA, SC, RA, CA, SA | 105 |
| [M1056 — Pre-compromise](/mitre/mitigations/M1056.md) | 84 | SC | 0 |
| [M1038 — Execution Prevention](/mitre/mitigations/M1038.md) | 80 | SI, CM, AC, SC, RA, IA, CA, SR | 61 |
| [M1042 — Disable or Remove Feature or Program](/mitre/mitigations/M1042.md) | 71 | CM, AC, SI, SC, IA, RA, CA, SR | 89 |
| [M1022 — Restrict File and Directory Permissions](/mitre/mitigations/M1022.md) | 61 | AC, CM, SI, CA, SC, IA, CP, RA | 73 |
| [M1017 — User Training](/mitre/mitigations/M1017.md) | 59 | AC, SI, CM, SC, IA, CA, SA, RA | 83 |
| [M1031 — Network Intrusion Prevention](/mitre/mitigations/M1031.md) | 59 | SI, SC, CM, AC, CA, SA, IA, RA | 52 |
| [M1040 — Behavior Prevention on Endpoint](/mitre/mitigations/M1040.md) | 51 | SI, CM, AC, SC, IA, CA, RA, CP | 58 |
| [M1037 — Filter Network Traffic](/mitre/mitigations/M1037.md) | 49 | AC, SI, CM, SC, CA, IA, SA, RA | 49 |
| [M1032 — Multi-factor Authentication](/mitre/mitigations/M1032.md) | 48 | AC, CM, IA, SI, SC, SA, CA, RA | 74 |
| [M1027 — Password Policies](/mitre/mitigations/M1027.md) | 47 | AC, CM, IA, SI, SC, SA, CA, RA | 72 |
| [M1051 — Update Software](/mitre/mitigations/M1051.md) | 42 | SI, AC, CM, SC, IA, RA, CA, SA | 86 |
| [M1028 — Operating System Configuration](/mitre/mitigations/M1028.md) | 39 | CM, AC, SI, IA, SC, RA, CA, SA | 83 |
| [M1030 — Network Segmentation](/mitre/mitigations/M1030.md) | 37 | AC, CM, SC, SI, IA, CA, RA, SA | 62 |
| [M1054 — Software Configuration](/mitre/mitigations/M1054.md) | 37 | AC, CM, SI, SC, IA, CA, RA, SA | 49 |
| [M1041 — Encrypt Sensitive Information](/mitre/mitigations/M1041.md) | 33 | AC, SI, CM, SC, IA, CP, CA, RA | 63 |
| [M1021 — Restrict Web-Based Content](/mitre/mitigations/M1021.md) | 31 | SI, CM, AC, SC, CA, IA, RA, SA | 63 |
| [M1049 — Antivirus/Antimalware](/mitre/mitigations/M1049.md) | 23 | SI, CM, AC, SC, IA, CA, RA | 38 |
| [M1045 — Code Signing](/mitre/mitigations/M1045.md) | 22 | CM, SI, AC, SR, IA, SA, RA, SC | 46 |
| [M1024 — Restrict Registry Permissions](/mitre/mitigations/M1024.md) | 20 | AC, CM, SI, IA, CA, SC, RA, SA | 41 |
| [M1035 — Limit Access to Resource Over Network](/mitre/mitigations/M1035.md) | 19 | AC, CM, SI, SC, IA, RA, CA, SA | 45 |
| [M1013 — Application Developer Guidance](/mitre/mitigations/M1013.md) | 17 | CM, SI, AC, SC, SA, IA, RA, CA | 62 |
| [M1033 — Limit Software Installation](/mitre/mitigations/M1033.md) | 17 | CM, SI, AC, CA, IA, SC, SA, RA | 24 |
| [M1015 — Active Directory Configuration](/mitre/mitigations/M1015.md) | 15 | AC, CM, IA, SI, SA, SC, CA, RA | 66 |
| [M1046 — Boot Integrity](/mitre/mitigations/M1046.md) | 14 | CM, AC, SI, IA, SA, SR, RA, SC | 20 |
| [M1048 — Application Isolation and Sandboxing](/mitre/mitigations/M1048.md) | 14 | SC, SI, AC, CM, RA, IA, CA, SA | 40 |
| [M1050 — Exploit Protection](/mitre/mitigations/M1050.md) | 12 | SC, SI, CM, AC, CA, RA, IA, SA | 56 |
| [M1057 — Data Loss Prevention](/mitre/mitigations/M1057.md) | 12 | AC, SC, SI, CM, SA, CA, SR, IA | 26 |
| [M1029 — Remote Data Storage](/mitre/mitigations/M1029.md) | 11 | AC, SI, CM, CP, SC, CA, IA, SA | 19 |
| [M1036 — Account Use Policies](/mitre/mitigations/M1036.md) | 10 | AC, IA, CM, SA, SI, SC, CA, RA | 47 |
| [M1043 — Credential Access Protection](/mitre/mitigations/M1043.md) | 10 | AC, CM, SI, IA, SC, SR, CA, SA | 38 |
| [M1053 — Data Backup](/mitre/mitigations/M1053.md) | 10 | CP, SI, AC, CM | 20 |
| [M1025 — Privileged Process Integrity](/mitre/mitigations/M1025.md) | 7 | AC, SI, CM, IA, SC, CA, CP, RA | 29 |
| [M1034 — Limit Hardware Installation](/mitre/mitigations/M1034.md) | 7 | AC, CM, SI, SC, MP, CA, RA, SA | 14 |
| [M1052 — User Account Control](/mitre/mitigations/M1052.md) | 7 | AC, CM, SI, IA, RA, CA, SC | 26 |
| [M1060 — Out-of-Band Communications Channel](/mitre/mitigations/M1060.md) | 7 | AC, CM, SI, SC, IA, CA, RA | 34 |
| [M1016 — Vulnerability Scanning](/mitre/mitigations/M1016.md) | 5 | CM, SC, SI, AC, CA, RA, SR, SA | 23 |
| [M1019 — Threat Intelligence Program](/mitre/mitigations/M1019.md) | 5 | SC, SI, CM, AC, RA, CA, IA | 33 |
| [M1020 — SSL/TLS Inspection](/mitre/mitigations/M1020.md) | 4 | SC, CM, SI, AC, CA | 23 |
| [M1044 — Restrict Library Loading](/mitre/mitigations/M1044.md) | 3 | SI, CM, AC, RA, SC, CA, IA | 15 |
| [M1055 — Do Not Mitigate](/mitre/mitigations/M1055.md) | 3 | - | 0 |
| [M1039 — Environment Variable Permissions](/mitre/mitigations/M1039.md) | 2 | CM, AC, SI, CA | 22 |

## Per-technique crosswalk (counts + links)

⭐ = observed in the Team Star Wolf 529-machine training corpus. Counts link out to the per-object pages.

| Technique | Tactic | Mitigations | NIST | D3FEND | CAPEC |
|---|---|---|---:|---:|---:|
| [T1001](/mitre/techniques/T1001.md) Data Obfuscation | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 11 | 0 |
| [T1001.001](/mitre/techniques/T1001-001.md) Junk Data | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 0 | 0 |
| [T1001.002](/mitre/techniques/T1001-002.md) Steganography | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 0 | 0 |
| [T1001.003](/mitre/techniques/T1001-003.md) Protocol or Service Impersonation | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 0 | 0 |
| [T1003](/mitre/techniques/T1003.md) OS Credential Dumping ⭐ | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1017](/mitre/mitigations/M1017.md) [M1025](/mitre/mitigations/M1025.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1028](/mitre/mitigations/M1028.md) +3 | 22 | 0 | 0 |
| [T1003.001](/mitre/techniques/T1003-001.md) LSASS Memory | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1025](/mitre/mitigations/M1025.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1028](/mitre/mitigations/M1028.md) [M1040](/mitre/mitigations/M1040.md) +1 | 19 | 12 | 0 |
| [T1003.002](/mitre/techniques/T1003-002.md) Security Account Manager | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1028](/mitre/mitigations/M1028.md) | 15 | 14 | 0 |
| [T1003.003](/mitre/techniques/T1003-003.md) NTDS | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1041](/mitre/mitigations/M1041.md) | 18 | 9 | 0 |
| [T1003.004](/mitre/techniques/T1003-004.md) LSA Secrets | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) | 14 | 13 | 0 |
| [T1003.005](/mitre/techniques/T1003-005.md) Cached Domain Credentials | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1017](/mitre/mitigations/M1017.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1028](/mitre/mitigations/M1028.md) | 17 | 10 | 0 |
| [T1003.006](/mitre/techniques/T1003-006.md) DCSync | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) | 16 | 13 | 0 |
| [T1003.007](/mitre/techniques/T1003-007.md) Proc Filesystem | credential-access | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) | 14 | 12 | 0 |
| [T1003.008](/mitre/techniques/T1003-008.md) /etc/passwd and /etc/shadow | credential-access | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) | 14 | 22 | 0 |
| [T1005](/mitre/techniques/T1005.md) Data from Local System | collection | [M1057](/mitre/mitigations/M1057.md) | 13 | 11 | 0 |
| [T1006](/mitre/techniques/T1006.md) Direct Volume Access | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1040](/mitre/mitigations/M1040.md) | 0 | 0 | 0 |
| [T1007](/mitre/techniques/T1007.md) System Service Discovery | discovery | - | 0 | 6 | 0 |
| [T1008](/mitre/techniques/T1008.md) Fallback Channels | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 8 | 11 | 0 |
| [T1010](/mitre/techniques/T1010.md) Application Window Discovery | discovery | - | 0 | 6 | 0 |
| [T1011](/mitre/techniques/T1011.md) Exfiltration Over Other Network Medium | exfiltration | [M1028](/mitre/mitigations/M1028.md) [M1042](/mitre/mitigations/M1042.md) | 5 | 9 | 0 |
| [T1011.001](/mitre/techniques/T1011-001.md) Exfiltration Over Bluetooth | exfiltration | [M1028](/mitre/mitigations/M1028.md) [M1042](/mitre/mitigations/M1042.md) | 8 | 0 | 0 |
| [T1012](/mitre/techniques/T1012.md) Query Registry | discovery | - | 0 | 5 | 0 |
| [T1014](/mitre/techniques/T1014.md) Rootkit | defense-evasion | - | 0 | 18 | 0 |
| [T1016](/mitre/techniques/T1016.md) System Network Configuration Discovery | discovery | - | 0 | 19 | 0 |
| [T1016.001](/mitre/techniques/T1016-001.md) Internet Connection Discovery | discovery | - | 0 | 0 | 0 |
| [T1016.002](/mitre/techniques/T1016-002.md) Wi-Fi Discovery | discovery | - | 0 | 0 | 0 |
| [T1018](/mitre/techniques/T1018.md) Remote System Discovery | discovery | - | 0 | 27 | 0 |
| [T1020](/mitre/techniques/T1020.md) Automated Exfiltration | exfiltration | - | 0 | 9 | 0 |
| [T1020.001](/mitre/techniques/T1020-001.md) Traffic Duplication | exfiltration | [M1018](/mitre/mitigations/M1018.md) [M1041](/mitre/mitigations/M1041.md) [M1057](/mitre/mitigations/M1057.md) | 21 | 0 | 0 |
| [T1021](/mitre/techniques/T1021.md) Remote Services | lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1035](/mitre/mitigations/M1035.md) [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) | 14 | 10 | 0 |
| [T1021.001](/mitre/techniques/T1021-001.md) Remote Desktop Protocol ⭐ | lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) [M1035](/mitre/mitigations/M1035.md) +2 | 23 | 10 | 0 |
| [T1021.002](/mitre/techniques/T1021-002.md) SMB/Windows Admin Shares | lateral-movement | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1035](/mitre/mitigations/M1035.md) [M1037](/mitre/mitigations/M1037.md) | 16 | 0 | 0 |
| [T1021.003](/mitre/techniques/T1021-003.md) Distributed Component Object Model | lateral-movement | [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1042](/mitre/mitigations/M1042.md) [M1048](/mitre/mitigations/M1048.md) | 19 | 0 | 0 |
| [T1021.004](/mitre/techniques/T1021-004.md) SSH ⭐ | lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1032](/mitre/mitigations/M1032.md) [M1042](/mitre/mitigations/M1042.md) | 15 | 10 | 0 |
| [T1021.005](/mitre/techniques/T1021-005.md) VNC | lateral-movement | [M1033](/mitre/mitigations/M1033.md) [M1037](/mitre/mitigations/M1037.md) [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) | 22 | 0 | 0 |
| [T1021.006](/mitre/techniques/T1021-006.md) Windows Remote Management | lateral-movement | [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1042](/mitre/mitigations/M1042.md) | 16 | 0 | 0 |
| [T1021.007](/mitre/techniques/T1021-007.md) Cloud Services | lateral-movement | [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) | 7 | 0 | 0 |
| [T1021.008](/mitre/techniques/T1021-008.md) Direct Cloud VM Connections | lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 0 | 0 |
| [T1025](/mitre/techniques/T1025.md) Data from Removable Media | collection | [M1057](/mitre/mitigations/M1057.md) | 15 | 3 | 0 |
| [T1027](/mitre/techniques/T1027.md) Obfuscated Files or Information | defense-evasion | [M1017](/mitre/mitigations/M1017.md) [M1040](/mitre/mitigations/M1040.md) [M1047](/mitre/mitigations/M1047.md) [M1049](/mitre/mitigations/M1049.md) | 8 | 0 | 0 |
| [T1027.001](/mitre/techniques/T1027-001.md) Binary Padding | defense-evasion | - | 0 | 15 | 0 |
| [T1027.002](/mitre/techniques/T1027-002.md) Software Packing | defense-evasion | [M1049](/mitre/mitigations/M1049.md) | 4 | 15 | 0 |
| [T1027.003](/mitre/techniques/T1027-003.md) Steganography | defense-evasion | - | 0 | 0 | 0 |
| [T1027.004](/mitre/techniques/T1027-004.md) Compile After Delivery | defense-evasion | - | 0 | 15 | 0 |
| [T1027.005](/mitre/techniques/T1027-005.md) Indicator Removal from Tools | defense-evasion | - | 0 | 0 | 0 |
| [T1027.006](/mitre/techniques/T1027-006.md) HTML Smuggling | defense-evasion | [M1048](/mitre/mitigations/M1048.md) | 0 | 0 | 0 |
| [T1027.007](/mitre/techniques/T1027-007.md) Dynamic API Resolution | defense-evasion | - | 4 | 0 | 0 |
| [T1027.008](/mitre/techniques/T1027-008.md) Stripped Payloads | defense-evasion | - | 4 | 0 | 0 |
| [T1027.009](/mitre/techniques/T1027-009.md) Embedded Payloads | defense-evasion | [M1040](/mitre/mitigations/M1040.md) [M1049](/mitre/mitigations/M1049.md) | 4 | 0 | 0 |
| [T1027.010](/mitre/techniques/T1027-010.md) Command Obfuscation | defense-evasion | [M1040](/mitre/mitigations/M1040.md) [M1049](/mitre/mitigations/M1049.md) | 4 | 0 | 0 |
| [T1027.011](/mitre/techniques/T1027-011.md) Fileless Storage | defense-evasion | [M1047](/mitre/mitigations/M1047.md) | 1 | 0 | 0 |
| [T1027.012](/mitre/techniques/T1027-012.md) LNK Icon Smuggling | defense-evasion | [M1040](/mitre/mitigations/M1040.md) [M1049](/mitre/mitigations/M1049.md) | 2 | 0 | 0 |
| [T1027.013](/mitre/techniques/T1027-013.md) Encrypted/Encoded File | defense-evasion | [M1040](/mitre/mitigations/M1040.md) [M1049](/mitre/mitigations/M1049.md) | 1 | 0 | 0 |
| [T1027.014](/mitre/techniques/T1027-014.md) Polymorphic Code | defense-evasion | [M1040](/mitre/mitigations/M1040.md) [M1049](/mitre/mitigations/M1049.md) | 1 | 0 | 0 |
| [T1027.015](/mitre/techniques/T1027-015.md) Compression | defense-evasion | [M1049](/mitre/mitigations/M1049.md) | 0 | 0 | 0 |
| [T1027.016](/mitre/techniques/T1027-016.md) Junk Code Insertion | defense-evasion | [M1049](/mitre/mitigations/M1049.md) | 0 | 0 | 0 |
| [T1027.017](/mitre/techniques/T1027-017.md) SVG Smuggling | defense-evasion | [M1048](/mitre/mitigations/M1048.md) | 0 | 0 | 0 |
| [T1029](/mitre/techniques/T1029.md) Scheduled Transfer | exfiltration | [M1031](/mitre/mitigations/M1031.md) | 7 | 9 | 0 |
| [T1030](/mitre/techniques/T1030.md) Data Transfer Size Limits | exfiltration | [M1031](/mitre/mitigations/M1031.md) | 7 | 9 | 0 |
| [T1033](/mitre/techniques/T1033.md) System Owner/User Discovery | discovery | - | 0 | 31 | 0 |
| [T1036](/mitre/techniques/T1036.md) Masquerading | defense-evasion | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) [M1045](/mitre/mitigations/M1045.md) +2 | 12 | 0 | 0 |
| [T1036.001](/mitre/techniques/T1036-001.md) Invalid Code Signature | defense-evasion | [M1045](/mitre/mitigations/M1045.md) | 5 | 15 | 0 |
| [T1036.002](/mitre/techniques/T1036-002.md) Right-to-Left Override | defense-evasion | - | 0 | 0 | 0 |
| [T1036.003](/mitre/techniques/T1036-003.md) Rename Legitimate Utilities | defense-evasion | [M1022](/mitre/mitigations/M1022.md) | 8 | 16 | 0 |
| [T1036.004](/mitre/techniques/T1036-004.md) Masquerade Task or Service | defense-evasion | - | 0 | 1 | 0 |
| [T1036.005](/mitre/techniques/T1036-005.md) Match Legitimate Resource Name or Location | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) [M1045](/mitre/mitigations/M1045.md) | 12 | 13 | 0 |
| [T1036.006](/mitre/techniques/T1036-006.md) Space after Filename | defense-evasion | - | 0 | 11 | 0 |
| [T1036.007](/mitre/techniques/T1036-007.md) Double File Extension | defense-evasion | [M1017](/mitre/mitigations/M1017.md) [M1028](/mitre/mitigations/M1028.md) | 6 | 0 | 0 |
| [T1036.008](/mitre/techniques/T1036-008.md) Masquerade File Type | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) [M1049](/mitre/mitigations/M1049.md) | 5 | 0 | 0 |
| [T1036.009](/mitre/techniques/T1036-009.md) Break Process Trees | defense-evasion | - | 0 | 0 | 0 |
| [T1036.010](/mitre/techniques/T1036-010.md) Masquerade Account Name | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 5 | 0 | 0 |
| [T1036.011](/mitre/techniques/T1036-011.md) Overwrite Process Arguments | defense-evasion | - | 0 | 0 | 0 |
| [T1036.012](/mitre/techniques/T1036-012.md) Browser Fingerprint | defense-evasion | [M1047](/mitre/mitigations/M1047.md) | 0 | 0 | 0 |
| [T1037](/mitre/techniques/T1037.md) Boot or Logon Initialization Scripts | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) | 9 | 0 | 0 |
| [T1037.001](/mitre/techniques/T1037-001.md) Logon Script (Windows) | persistence, privilege-escalation | [M1024](/mitre/mitigations/M1024.md) | 2 | 15 | 0 |
| [T1037.002](/mitre/techniques/T1037-002.md) Login Hook | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 7 | 15 | 0 |
| [T1037.003](/mitre/techniques/T1037-003.md) Network Logon Script | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 7 | 17 | 0 |
| [T1037.004](/mitre/techniques/T1037-004.md) RC Scripts | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 7 | 18 | 0 |
| [T1037.005](/mitre/techniques/T1037-005.md) Startup Items | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 7 | 4 | 0 |
| [T1039](/mitre/techniques/T1039.md) Data from Network Shared Drive | collection | - | 0 | 2 | 0 |
| [T1040](/mitre/techniques/T1040.md) Network Sniffing | credential-access, discovery | [M1018](/mitre/mitigations/M1018.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) [M1041](/mitre/mitigations/M1041.md) | 12 | 1 | 0 |
| [T1041](/mitre/techniques/T1041.md) Exfiltration Over C2 Channel | exfiltration | [M1031](/mitre/mitigations/M1031.md) [M1057](/mitre/mitigations/M1057.md) | 18 | 21 | 0 |
| [T1046](/mitre/techniques/T1046.md) Network Service Discovery ⭐ | discovery | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 0 | 0 |
| [T1047](/mitre/techniques/T1047.md) Windows Management Instrumentation | execution | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) | 17 | 17 | 0 |
| [T1048](/mitre/techniques/T1048.md) Exfiltration Over Alternative Protocol | exfiltration | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1057](/mitre/mitigations/M1057.md) | 23 | 9 | 0 |
| [T1048.001](/mitre/techniques/T1048-001.md) Exfiltration Over Symmetric Encrypted Non-C2 Protocol | exfiltration | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 12 | 11 | 0 |
| [T1048.002](/mitre/techniques/T1048-002.md) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | exfiltration | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1057](/mitre/mitigations/M1057.md) | 23 | 23 | 0 |
| [T1048.003](/mitre/techniques/T1048-003.md) Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1057](/mitre/mitigations/M1057.md) | 23 | 11 | 0 |
| [T1049](/mitre/techniques/T1049.md) System Network Connections Discovery | discovery | - | 0 | 2 | 0 |
| [T1052](/mitre/techniques/T1052.md) Exfiltration Over Physical Medium | exfiltration | [M1034](/mitre/mitigations/M1034.md) [M1042](/mitre/mitigations/M1042.md) [M1057](/mitre/mitigations/M1057.md) | 19 | 0 | 0 |
| [T1052.001](/mitre/techniques/T1052-001.md) Exfiltration over USB | exfiltration | [M1034](/mitre/mitigations/M1034.md) [M1042](/mitre/mitigations/M1042.md) [M1057](/mitre/mitigations/M1057.md) | 19 | 3 | 0 |
| [T1053](/mitre/techniques/T1053.md) Scheduled Task/Job | execution, persistence | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1047](/mitre/mitigations/M1047.md) | 14 | 16 | 0 |
| [T1053.002](/mitre/techniques/T1053-002.md) At | execution, persistence | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1047](/mitre/mitigations/M1047.md) | 13 | 0 | 0 |
| [T1053.003](/mitre/techniques/T1053-003.md) Cron ⭐ | execution, persistence | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 9 | 0 | 0 |
| [T1053.005](/mitre/techniques/T1053-005.md) Scheduled Task | execution, persistence | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1047](/mitre/mitigations/M1047.md) | 13 | 12 | 0 |
| [T1053.006](/mitre/techniques/T1053-006.md) Systemd Timers | execution, persistence | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) | 10 | 0 | 0 |
| [T1053.007](/mitre/techniques/T1053-007.md) Container Orchestration Job | execution, persistence | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) | 7 | 0 | 0 |
| [T1055](/mitre/techniques/T1055.md) Process Injection | defense-evasion, privilege-escalation | [M1026](/mitre/mitigations/M1026.md) [M1040](/mitre/mitigations/M1040.md) | 12 | 0 | 0 |
| [T1055.001](/mitre/techniques/T1055-001.md) Dynamic-link Library Injection | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 13 | 0 |
| [T1055.002](/mitre/techniques/T1055-002.md) Portable Executable Injection | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 11 | 0 |
| [T1055.003](/mitre/techniques/T1055-003.md) Thread Execution Hijacking | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 17 | 0 |
| [T1055.004](/mitre/techniques/T1055-004.md) Asynchronous Procedure Call | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 6 | 0 |
| [T1055.005](/mitre/techniques/T1055-005.md) Thread Local Storage | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 2 | 0 |
| [T1055.008](/mitre/techniques/T1055-008.md) Ptrace System Calls | defense-evasion, privilege-escalation | [M1026](/mitre/mitigations/M1026.md) [M1040](/mitre/mitigations/M1040.md) | 12 | 2 | 0 |
| [T1055.009](/mitre/techniques/T1055-009.md) Proc Memory | defense-evasion, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1040](/mitre/mitigations/M1040.md) | 9 | 12 | 0 |
| [T1055.011](/mitre/techniques/T1055-011.md) Extra Window Memory Injection | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 0 | 0 |
| [T1055.012](/mitre/techniques/T1055-012.md) Process Hollowing | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 4 | 0 |
| [T1055.013](/mitre/techniques/T1055-013.md) Process Doppelgänging | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 6 | 0 |
| [T1055.014](/mitre/techniques/T1055-014.md) VDSO Hijacking | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 6 | 13 | 0 |
| [T1055.015](/mitre/techniques/T1055-015.md) ListPlanting | defense-evasion, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 1 | 0 | 0 |
| [T1056](/mitre/techniques/T1056.md) Input Capture | collection, credential-access | - | 0 | 0 | 0 |
| [T1056.001](/mitre/techniques/T1056-001.md) Keylogging | collection, credential-access | - | 0 | 4 | 0 |
| [T1056.002](/mitre/techniques/T1056-002.md) GUI Input Capture | collection, credential-access | [M1017](/mitre/mitigations/M1017.md) | 4 | 0 | 0 |
| [T1056.003](/mitre/techniques/T1056-003.md) Web Portal Capture | collection, credential-access | [M1026](/mitre/mitigations/M1026.md) | 7 | 5 | 0 |
| [T1056.004](/mitre/techniques/T1056-004.md) Credential API Hooking | collection, credential-access | - | 0 | 4 | 0 |
| [T1057](/mitre/techniques/T1057.md) Process Discovery | discovery | - | 0 | 6 | 0 |
| [T1059](/mitre/techniques/T1059.md) Command and Scripting Interpreter | execution | [M1021](/mitre/mitigations/M1021.md) [M1026](/mitre/mitigations/M1026.md) [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) +3 | 23 | 15 | 0 |
| [T1059.001](/mitre/techniques/T1059-001.md) PowerShell ⭐ | execution | [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) [M1045](/mitre/mitigations/M1045.md) [M1049](/mitre/mitigations/M1049.md) | 19 | 0 | 0 |
| [T1059.002](/mitre/techniques/T1059-002.md) AppleScript | execution | [M1038](/mitre/mitigations/M1038.md) [M1045](/mitre/mitigations/M1045.md) | 15 | 0 | 0 |
| [T1059.003](/mitre/techniques/T1059-003.md) Windows Command Shell | execution | [M1038](/mitre/mitigations/M1038.md) | 11 | 0 | 0 |
| [T1059.004](/mitre/techniques/T1059-004.md) Unix Shell | execution | [M1038](/mitre/mitigations/M1038.md) | 11 | 0 | 0 |
| [T1059.005](/mitre/techniques/T1059-005.md) Visual Basic | execution | [M1021](/mitre/mitigations/M1021.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) [M1049](/mitre/mitigations/M1049.md) | 17 | 0 | 0 |
| [T1059.006](/mitre/techniques/T1059-006.md) Python | execution | [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) [M1049](/mitre/mitigations/M1049.md) | 15 | 0 | 0 |
| [T1059.007](/mitre/techniques/T1059-007.md) JavaScript | execution | [M1021](/mitre/mitigations/M1021.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) | 16 | 0 | 0 |
| [T1059.008](/mitre/techniques/T1059-008.md) Network Device CLI | execution | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) | 15 | 0 | 0 |
| [T1059.009](/mitre/techniques/T1059-009.md) Cloud API | execution | [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) | 6 | 0 | 0 |
| [T1059.010](/mitre/techniques/T1059-010.md) AutoHotKey & AutoIT | execution | [M1038](/mitre/mitigations/M1038.md) | 11 | 0 | 0 |
| [T1059.011](/mitre/techniques/T1059-011.md) Lua | execution | [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) | 9 | 0 | 0 |
| [T1059.012](/mitre/techniques/T1059-012.md) Hypervisor CLI | execution | - | 0 | 0 | 0 |
| [T1059.013](/mitre/techniques/T1059-013.md) Container CLI/API | execution | [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) | 0 | 0 | 0 |
| [T1068](/mitre/techniques/T1068.md) Exploitation for Privilege Escalation ⭐ | privilege-escalation | [M1019](/mitre/mitigations/M1019.md) [M1038](/mitre/mitigations/M1038.md) [M1048](/mitre/mitigations/M1048.md) [M1050](/mitre/mitigations/M1050.md) [M1051](/mitre/mitigations/M1051.md) | 21 | 6 | 0 |
| [T1069](/mitre/techniques/T1069.md) Permission Groups Discovery | discovery | - | 0 | 0 | 0 |
| [T1069.001](/mitre/techniques/T1069-001.md) Local Groups | discovery | - | 0 | 0 | 0 |
| [T1069.002](/mitre/techniques/T1069-002.md) Domain Groups | discovery | - | 0 | 0 | 0 |
| [T1069.003](/mitre/techniques/T1069-003.md) Cloud Groups | discovery | - | 0 | 0 | 0 |
| [T1070](/mitre/techniques/T1070.md) Indicator Removal | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1041](/mitre/mitigations/M1041.md) | 20 | 0 | 0 |
| [T1070.001](/mitre/techniques/T1070-001.md) Clear Windows Event Logs | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1041](/mitre/mitigations/M1041.md) | 21 | 2 | 0 |
| [T1070.002](/mitre/techniques/T1070-002.md) Clear Linux or Mac System Logs | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1041](/mitre/mitigations/M1041.md) | 21 | 12 | 0 |
| [T1070.003](/mitre/techniques/T1070-003.md) Clear Command History | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1039](/mitre/mitigations/M1039.md) | 10 | 2 | 0 |
| [T1070.004](/mitre/techniques/T1070-004.md) File Deletion | defense-evasion | - | 0 | 11 | 0 |
| [T1070.005](/mitre/techniques/T1070-005.md) Network Share Connection Removal | defense-evasion | - | 0 | 2 | 0 |
| [T1070.006](/mitre/techniques/T1070-006.md) Timestomp | defense-evasion | - | 0 | 0 | 0 |
| [T1070.007](/mitre/techniques/T1070-007.md) Clear Network Connection History and Configurations | defense-evasion | [M1024](/mitre/mitigations/M1024.md) [M1029](/mitre/mitigations/M1029.md) | 10 | 0 | 0 |
| [T1070.008](/mitre/techniques/T1070-008.md) Clear Mailbox Data | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1047](/mitre/mitigations/M1047.md) | 22 | 0 | 0 |
| [T1070.009](/mitre/techniques/T1070-009.md) Clear Persistence | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) | 10 | 0 | 0 |
| [T1070.010](/mitre/techniques/T1070-010.md) Relocate Malware | defense-evasion | - | 3 | 0 | 0 |
| [T1071](/mitre/techniques/T1071.md) Application Layer Protocol | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 15 | 23 | 0 |
| [T1071.001](/mitre/techniques/T1071-001.md) Web Protocols | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 15 | 23 | 0 |
| [T1071.002](/mitre/techniques/T1071-002.md) File Transfer Protocols | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 15 | 12 | 0 |
| [T1071.003](/mitre/techniques/T1071-003.md) Mail Protocols | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 15 | 11 | 0 |
| [T1071.004](/mitre/techniques/T1071-004.md) DNS | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 18 | 16 | 0 |
| [T1071.005](/mitre/techniques/T1071-005.md) Publish/Subscribe Protocols | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 4 | 0 | 0 |
| [T1072](/mitre/techniques/T1072.md) Software Deployment Tools | execution, lateral-movement | [M1015](/mitre/mitigations/M1015.md) [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1029](/mitre/mitigations/M1029.md) +4 | 27 | 16 | 0 |
| [T1074](/mitre/techniques/T1074.md) Data Staged | collection | - | 0 | 0 | 0 |
| [T1074.001](/mitre/techniques/T1074-001.md) Local Data Staging | collection | - | 0 | 14 | 0 |
| [T1074.002](/mitre/techniques/T1074-002.md) Remote Data Staging | collection | - | 0 | 2 | 0 |
| [T1078](/mitre/techniques/T1078.md) Valid Accounts ⭐ | defense-evasion, persistence | [M1013](/mitre/mitigations/M1013.md) [M1015](/mitre/mitigations/M1015.md) [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) +2 | 25 | 7 | 0 |
| [T1078.001](/mitre/techniques/T1078-001.md) Default Accounts | defense-evasion, persistence | [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) | 14 | 7 | 0 |
| [T1078.002](/mitre/techniques/T1078-002.md) Domain Accounts | defense-evasion, persistence | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) | 13 | 8 | 0 |
| [T1078.003](/mitre/techniques/T1078-003.md) Local Accounts | defense-evasion, persistence | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) | 19 | 8 | 0 |
| [T1078.004](/mitre/techniques/T1078-004.md) Cloud Accounts | defense-evasion, persistence | [M1015](/mitre/mitigations/M1015.md) [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) +1 | 24 | 7 | 0 |
| [T1080](/mitre/techniques/T1080.md) Taint Shared Content | lateral-movement | [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) [M1049](/mitre/mitigations/M1049.md) [M1050](/mitre/mitigations/M1050.md) | 10 | 2 | 0 |
| [T1082](/mitre/techniques/T1082.md) System Information Discovery | discovery | - | 0 | 7 | 0 |
| [T1083](/mitre/techniques/T1083.md) File and Directory Discovery ⭐ | discovery | - | 0 | 11 | 0 |
| [T1087](/mitre/techniques/T1087.md) Account Discovery | discovery | [M1018](/mitre/mitigations/M1018.md) [M1028](/mitre/mitigations/M1028.md) | 4 | 0 | 0 |
| [T1087.001](/mitre/techniques/T1087-001.md) Local Account | discovery | [M1028](/mitre/mitigations/M1028.md) | 3 | 8 | 0 |
| [T1087.002](/mitre/techniques/T1087-002.md) Domain Account | discovery | [M1028](/mitre/mitigations/M1028.md) | 3 | 8 | 0 |
| [T1087.003](/mitre/techniques/T1087-003.md) Email Account | discovery | - | 0 | 0 | 0 |
| [T1087.004](/mitre/techniques/T1087-004.md) Cloud Account | discovery | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 6 | 7 | 0 |
| [T1090](/mitre/techniques/T1090.md) Proxy | command-and-control | [M1020](/mitre/mitigations/M1020.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 12 | 0 | 0 |
| [T1090.001](/mitre/techniques/T1090-001.md) Internal Proxy | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 8 | 10 | 0 |
| [T1090.002](/mitre/techniques/T1090-002.md) External Proxy | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 8 | 11 | 0 |
| [T1090.003](/mitre/techniques/T1090-003.md) Multi-hop Proxy | command-and-control | [M1037](/mitre/mitigations/M1037.md) | 8 | 11 | 0 |
| [T1090.004](/mitre/techniques/T1090-004.md) Domain Fronting | command-and-control | [M1020](/mitre/mitigations/M1020.md) | 1 | 11 | 0 |
| [T1091](/mitre/techniques/T1091.md) Replication Through Removable Media | lateral-movement, initial-access | [M1034](/mitre/mitigations/M1034.md) [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) | 10 | 3 | 0 |
| [T1092](/mitre/techniques/T1092.md) Communication Through Removable Media | command-and-control | [M1028](/mitre/mitigations/M1028.md) [M1042](/mitre/mitigations/M1042.md) | 8 | 3 | 0 |
| [T1095](/mitre/techniques/T1095.md) Non-Application Layer Protocol | command-and-control | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 11 | 0 |
| [T1098](/mitre/techniques/T1098.md) Account Manipulation | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) +1 | 11 | 7 | 0 |
| [T1098.001](/mitre/techniques/T1098-001.md) Additional Cloud Credentials | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) [M1042](/mitre/mitigations/M1042.md) | 15 | 20 | 0 |
| [T1098.002](/mitre/techniques/T1098-002.md) Additional Email Delegate Permissions | persistence, privilege-escalation | [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 8 | 0 |
| [T1098.003](/mitre/techniques/T1098-003.md) Additional Cloud Roles | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) | 11 | 8 | 0 |
| [T1098.004](/mitre/techniques/T1098-004.md) SSH Authorized Keys | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1042](/mitre/mitigations/M1042.md) | 15 | 0 | 0 |
| [T1098.005](/mitre/techniques/T1098-005.md) Device Registration | persistence, privilege-escalation | [M1032](/mitre/mitigations/M1032.md) | 7 | 0 | 0 |
| [T1098.006](/mitre/techniques/T1098-006.md) Additional Container Cluster Roles | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1032](/mitre/mitigations/M1032.md) | 4 | 0 | 0 |
| [T1098.007](/mitre/techniques/T1098-007.md) Additional Local or Domain Groups | persistence, privilege-escalation | - | 11 | 0 | 0 |
| [T1102](/mitre/techniques/T1102.md) Web Service | command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 11 | 0 |
| [T1102.001](/mitre/techniques/T1102-001.md) Dead Drop Resolver | command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 0 | 0 |
| [T1102.002](/mitre/techniques/T1102-002.md) Bidirectional Communication | command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 0 | 0 |
| [T1102.003](/mitre/techniques/T1102-003.md) One-Way Communication | command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 0 | 0 |
| [T1104](/mitre/techniques/T1104.md) Multi-Stage Channels | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 8 | 11 | 0 |
| [T1105](/mitre/techniques/T1105.md) Ingress Tool Transfer ⭐ | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 8 | 11 | 0 |
| [T1106](/mitre/techniques/T1106.md) Native API | execution | [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) | 7 | 2 | 0 |
| [T1110](/mitre/techniques/T1110.md) Brute Force | credential-access | [M1018](/mitre/mitigations/M1018.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1036](/mitre/mitigations/M1036.md) | 14 | 0 | 0 |
| [T1110.001](/mitre/techniques/T1110-001.md) Password Guessing | credential-access | [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1036](/mitre/mitigations/M1036.md) [M1051](/mitre/mitigations/M1051.md) | 14 | 16 | 0 |
| [T1110.002](/mitre/techniques/T1110-002.md) Password Cracking ⭐ | credential-access | [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) | 14 | 14 | 0 |
| [T1110.003](/mitre/techniques/T1110-003.md) Password Spraying | credential-access | [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1036](/mitre/mitigations/M1036.md) | 14 | 27 | 0 |
| [T1110.004](/mitre/techniques/T1110-004.md) Credential Stuffing | credential-access | [M1018](/mitre/mitigations/M1018.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1036](/mitre/mitigations/M1036.md) | 14 | 13 | 0 |
| [T1111](/mitre/techniques/T1111.md) Multi-Factor Authentication Interception | credential-access | [M1017](/mitre/mitigations/M1017.md) | 9 | 2 | 0 |
| [T1112](/mitre/techniques/T1112.md) Modify Registry | defense-evasion, persistence | [M1024](/mitre/mitigations/M1024.md) | 3 | 3 | 0 |
| [T1113](/mitre/techniques/T1113.md) Screen Capture | collection | - | 0 | 2 | 0 |
| [T1114](/mitre/techniques/T1114.md) Email Collection | collection | [M1032](/mitre/mitigations/M1032.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) [M1060](/mitre/mitigations/M1060.md) | 15 | 0 | 0 |
| [T1114.001](/mitre/techniques/T1114-001.md) Local Email Collection | collection | [M1041](/mitre/mitigations/M1041.md) [M1060](/mitre/mitigations/M1060.md) | 9 | 20 | 0 |
| [T1114.002](/mitre/techniques/T1114-002.md) Remote Email Collection | collection | [M1032](/mitre/mitigations/M1032.md) [M1041](/mitre/mitigations/M1041.md) [M1060](/mitre/mitigations/M1060.md) | 14 | 6 | 0 |
| [T1114.003](/mitre/techniques/T1114-003.md) Email Forwarding Rule | collection | [M1041](/mitre/mitigations/M1041.md) [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) [M1060](/mitre/mitigations/M1060.md) | 12 | 4 | 0 |
| [T1115](/mitre/techniques/T1115.md) Clipboard Data | collection | - | 0 | 0 | 0 |
| [T1119](/mitre/techniques/T1119.md) Automated Collection | collection | [M1029](/mitre/mitigations/M1029.md) [M1041](/mitre/mitigations/M1041.md) | 17 | 11 | 0 |
| [T1120](/mitre/techniques/T1120.md) Peripheral Device Discovery | discovery | - | 0 | 0 | 0 |
| [T1123](/mitre/techniques/T1123.md) Audio Capture | collection | - | 0 | 4 | 0 |
| [T1124](/mitre/techniques/T1124.md) System Time Discovery | discovery | - | 0 | 6 | 0 |
| [T1125](/mitre/techniques/T1125.md) Video Capture | collection | - | 0 | 5 | 0 |
| [T1127](/mitre/techniques/T1127.md) Trusted Developer Utilities Proxy Execution | defense-evasion | [M1021](/mitre/mitigations/M1021.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 8 | 0 | 0 |
| [T1127.001](/mitre/techniques/T1127-001.md) MSBuild | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 5 | 15 | 0 |
| [T1127.002](/mitre/techniques/T1127-002.md) ClickOnce | defense-evasion | [M1021](/mitre/mitigations/M1021.md) [M1042](/mitre/mitigations/M1042.md) [M1045](/mitre/mitigations/M1045.md) | 10 | 0 | 0 |
| [T1127.003](/mitre/techniques/T1127-003.md) JamPlus | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 0 | 0 | 0 |
| [T1129](/mitre/techniques/T1129.md) Shared Modules | execution | [M1038](/mitre/mitigations/M1038.md) | 6 | 0 | 0 |
| [T1132](/mitre/techniques/T1132.md) Data Encoding | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 11 | 0 |
| [T1132.001](/mitre/techniques/T1132-001.md) Standard Encoding | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 0 | 0 |
| [T1132.002](/mitre/techniques/T1132-002.md) Non-Standard Encoding | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 7 | 0 | 0 |
| [T1133](/mitre/techniques/T1133.md) External Remote Services | persistence, initial-access | [M1021](/mitre/mitigations/M1021.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) [M1035](/mitre/mitigations/M1035.md) [M1042](/mitre/mitigations/M1042.md) | 17 | 1 | 0 |
| [T1134](/mitre/techniques/T1134.md) Access Token Manipulation | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) | 8 | 0 | 0 |
| [T1134.001](/mitre/techniques/T1134-001.md) Token Impersonation/Theft | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) | 8 | 11 | 0 |
| [T1134.002](/mitre/techniques/T1134-002.md) Create Process with Token | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) | 7 | 13 | 0 |
| [T1134.003](/mitre/techniques/T1134-003.md) Make and Impersonate Token | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) | 8 | 14 | 0 |
| [T1134.004](/mitre/techniques/T1134-004.md) Parent PID Spoofing | defense-evasion, privilege-escalation | - | 0 | 6 | 0 |
| [T1134.005](/mitre/techniques/T1134-005.md) SID-History Injection | defense-evasion, privilege-escalation | [M1015](/mitre/mitigations/M1015.md) | 13 | 4 | 0 |
| [T1135](/mitre/techniques/T1135.md) Network Share Discovery | discovery | [M1028](/mitre/mitigations/M1028.md) | 3 | 0 | 0 |
| [T1136](/mitre/techniques/T1136.md) Create Account | persistence | [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) | 15 | 7 | 0 |
| [T1136.001](/mitre/techniques/T1136-001.md) Local Account | persistence | [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) | 11 | 8 | 0 |
| [T1136.002](/mitre/techniques/T1136-002.md) Domain Account | persistence | [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) | 15 | 8 | 0 |
| [T1136.003](/mitre/techniques/T1136-003.md) Cloud Account | persistence | [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) | 14 | 7 | 0 |
| [T1137](/mitre/techniques/T1137.md) Office Application Startup | persistence | [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) [M1051](/mitre/mitigations/M1051.md) [M1054](/mitre/mitigations/M1054.md) | 13 | 0 | 0 |
| [T1137.001](/mitre/techniques/T1137-001.md) Office Template Macros | persistence | [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) | 10 | 17 | 0 |
| [T1137.002](/mitre/techniques/T1137-002.md) Office Test | persistence | [M1040](/mitre/mitigations/M1040.md) [M1054](/mitre/mitigations/M1054.md) | 10 | 3 | 0 |
| [T1137.003](/mitre/techniques/T1137-003.md) Outlook Forms | persistence | [M1040](/mitre/mitigations/M1040.md) [M1051](/mitre/mitigations/M1051.md) | 7 | 14 | 0 |
| [T1137.004](/mitre/techniques/T1137-004.md) Outlook Home Page | persistence | [M1040](/mitre/mitigations/M1040.md) [M1051](/mitre/mitigations/M1051.md) | 7 | 2 | 0 |
| [T1137.005](/mitre/techniques/T1137-005.md) Outlook Rules | persistence | [M1040](/mitre/mitigations/M1040.md) [M1051](/mitre/mitigations/M1051.md) | 7 | 2 | 0 |
| [T1137.006](/mitre/techniques/T1137-006.md) Add-ins | persistence | [M1040](/mitre/mitigations/M1040.md) | 6 | 7 | 0 |
| [T1140](/mitre/techniques/T1140.md) Deobfuscate/Decode Files or Information | defense-evasion | - | 0 | 21 | 0 |
| [T1176](/mitre/techniques/T1176.md) Software Extensions | persistence | [M1017](/mitre/mitigations/M1017.md) [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 14 | 4 | 0 |
| [T1176.001](/mitre/techniques/T1176-001.md) Browser Extensions | persistence | [M1017](/mitre/mitigations/M1017.md) [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 0 | 0 | 0 |
| [T1176.002](/mitre/techniques/T1176-002.md) IDE Extensions | persistence | [M1017](/mitre/mitigations/M1017.md) [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 0 | 0 | 0 |
| [T1185](/mitre/techniques/T1185.md) Browser Session Hijacking | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) | 14 | 9 | 0 |
| [T1187](/mitre/techniques/T1187.md) Forced Authentication | credential-access | [M1027](/mitre/mitigations/M1027.md) [M1037](/mitre/mitigations/M1037.md) | 10 | 13 | 0 |
| [T1189](/mitre/techniques/T1189.md) Drive-by Compromise | initial-access | [M1017](/mitre/mitigations/M1017.md) [M1021](/mitre/mitigations/M1021.md) [M1048](/mitre/mitigations/M1048.md) [M1050](/mitre/mitigations/M1050.md) [M1051](/mitre/mitigations/M1051.md) | 18 | 15 | 0 |
| [T1190](/mitre/techniques/T1190.md) Exploit Public-Facing Application ⭐ | initial-access | [M1016](/mitre/mitigations/M1016.md) [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1035](/mitre/mitigations/M1035.md) [M1037](/mitre/mitigations/M1037.md) [M1048](/mitre/mitigations/M1048.md) +2 | 29 | 14 | 0 |
| [T1195](/mitre/techniques/T1195.md) Supply Chain Compromise | initial-access | [M1013](/mitre/mitigations/M1013.md) [M1016](/mitre/mitigations/M1016.md) [M1018](/mitre/mitigations/M1018.md) [M1033](/mitre/mitigations/M1033.md) [M1046](/mitre/mitigations/M1046.md) [M1051](/mitre/mitigations/M1051.md) | 22 | 0 | 0 |
| [T1195.001](/mitre/techniques/T1195-001.md) Compromise Software Dependencies and Development Tools | initial-access | [M1013](/mitre/mitigations/M1013.md) [M1016](/mitre/mitigations/M1016.md) [M1033](/mitre/mitigations/M1033.md) [M1051](/mitre/mitigations/M1051.md) | 18 | 4 | 0 |
| [T1195.002](/mitre/techniques/T1195-002.md) Compromise Software Supply Chain | initial-access | [M1016](/mitre/mitigations/M1016.md) [M1051](/mitre/mitigations/M1051.md) | 11 | 4 | 0 |
| [T1195.003](/mitre/techniques/T1195-003.md) Compromise Hardware Supply Chain | initial-access | [M1046](/mitre/mitigations/M1046.md) | 14 | 2 | 0 |
| [T1197](/mitre/techniques/T1197.md) BITS Jobs | defense-evasion, persistence | [M1018](/mitre/mitigations/M1018.md) [M1028](/mitre/mitigations/M1028.md) [M1037](/mitre/mitigations/M1037.md) | 14 | 13 | 0 |
| [T1199](/mitre/techniques/T1199.md) Trusted Relationship | initial-access | [M1018](/mitre/mitigations/M1018.md) [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) | 8 | 11 | 0 |
| [T1200](/mitre/techniques/T1200.md) Hardware Additions | initial-access | [M1034](/mitre/mitigations/M1034.md) [M1035](/mitre/mitigations/M1035.md) | 5 | 2 | 0 |
| [T1201](/mitre/techniques/T1201.md) Password Policy Discovery | discovery | [M1027](/mitre/mitigations/M1027.md) | 5 | 0 | 0 |
| [T1202](/mitre/techniques/T1202.md) Indirect Command Execution | defense-evasion | - | 0 | 0 | 0 |
| [T1203](/mitre/techniques/T1203.md) Exploitation for Client Execution | execution | [M1048](/mitre/mitigations/M1048.md) [M1050](/mitre/mitigations/M1050.md) [M1051](/mitre/mitigations/M1051.md) | 16 | 6 | 0 |
| [T1204](/mitre/techniques/T1204.md) User Execution | execution | [M1017](/mitre/mitigations/M1017.md) [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) | 13 | 0 | 0 |
| [T1204.001](/mitre/techniques/T1204-001.md) Malicious Link | execution | [M1017](/mitre/mitigations/M1017.md) [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 11 | 15 | 0 |
| [T1204.002](/mitre/techniques/T1204-002.md) Malicious File | execution | [M1017](/mitre/mitigations/M1017.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) | 12 | 15 | 0 |
| [T1204.003](/mitre/techniques/T1204-003.md) Malicious Image | execution | [M1017](/mitre/mitigations/M1017.md) [M1031](/mitre/mitigations/M1031.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 16 | 0 | 0 |
| [T1204.004](/mitre/techniques/T1204-004.md) Malicious Copy and Paste | execution | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) [M1038](/mitre/mitigations/M1038.md) | 0 | 0 | 0 |
| [T1204.005](/mitre/techniques/T1204-005.md) Malicious Library | execution | [M1017](/mitre/mitigations/M1017.md) [M1031](/mitre/mitigations/M1031.md) [M1033](/mitre/mitigations/M1033.md) | 0 | 0 | 0 |
| [T1205](/mitre/techniques/T1205.md) Traffic Signaling | defense-evasion, persistence | [M1037](/mitre/mitigations/M1037.md) [M1042](/mitre/mitigations/M1042.md) | 9 | 9 | 0 |
| [T1205.001](/mitre/techniques/T1205-001.md) Port Knocking | defense-evasion, persistence | [M1037](/mitre/mitigations/M1037.md) | 8 | 9 | 0 |
| [T1205.002](/mitre/techniques/T1205-002.md) Socket Filters | defense-evasion, persistence | [M1037](/mitre/mitigations/M1037.md) | 2 | 0 | 0 |
| [T1207](/mitre/techniques/T1207.md) Rogue Domain Controller | defense-evasion | - | 0 | 14 | 0 |
| [T1210](/mitre/techniques/T1210.md) Exploitation of Remote Services | lateral-movement | [M1016](/mitre/mitigations/M1016.md) [M1019](/mitre/mitigations/M1019.md) [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1042](/mitre/mitigations/M1042.md) [M1048](/mitre/mitigations/M1048.md) +2 | 31 | 16 | 0 |
| [T1211](/mitre/techniques/T1211.md) Exploitation for Defense Evasion | defense-evasion | [M1019](/mitre/mitigations/M1019.md) [M1048](/mitre/mitigations/M1048.md) [M1050](/mitre/mitigations/M1050.md) [M1051](/mitre/mitigations/M1051.md) | 22 | 6 | 0 |
| [T1212](/mitre/techniques/T1212.md) Exploitation for Credential Access | credential-access | [M1013](/mitre/mitigations/M1013.md) [M1019](/mitre/mitigations/M1019.md) [M1048](/mitre/mitigations/M1048.md) [M1050](/mitre/mitigations/M1050.md) [M1051](/mitre/mitigations/M1051.md) | 24 | 23 | 0 |
| [T1213](/mitre/techniques/T1213.md) Data from Information Repositories ⭐ | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1032](/mitre/mitigations/M1032.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) +1 | 24 | 0 | 0 |
| [T1213.001](/mitre/techniques/T1213-001.md) Confluence | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 23 | 2 | 0 |
| [T1213.002](/mitre/techniques/T1213-002.md) Sharepoint | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 23 | 2 | 0 |
| [T1213.003](/mitre/techniques/T1213-003.md) Code Repositories | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1032](/mitre/mitigations/M1032.md) [M1047](/mitre/mitigations/M1047.md) | 14 | 2 | 0 |
| [T1213.004](/mitre/techniques/T1213-004.md) Customer Relationship Management Software | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) | 18 | 0 | 0 |
| [T1213.005](/mitre/techniques/T1213-005.md) Messaging Applications | collection | [M1017](/mitre/mitigations/M1017.md) [M1047](/mitre/mitigations/M1047.md) [M1060](/mitre/mitigations/M1060.md) | 24 | 0 | 0 |
| [T1213.006](/mitre/techniques/T1213-006.md) Databases | collection | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) | 0 | 0 | 0 |
| [T1216](/mitre/techniques/T1216.md) System Script Proxy Execution | defense-evasion | [M1038](/mitre/mitigations/M1038.md) | 6 | 0 | 0 |
| [T1216.001](/mitre/techniques/T1216-001.md) PubPrn | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) | 6 | 0 | 0 |
| [T1216.002](/mitre/techniques/T1216-002.md) SyncAppvPublishingServer | defense-evasion | [M1038](/mitre/mitigations/M1038.md) | 4 | 0 | 0 |
| [T1217](/mitre/techniques/T1217.md) Browser Information Discovery | discovery | - | 0 | 0 | 0 |
| [T1218](/mitre/techniques/T1218.md) System Binary Proxy Execution | defense-evasion | [M1021](/mitre/mitigations/M1021.md) [M1026](/mitre/mitigations/M1026.md) [M1037](/mitre/mitigations/M1037.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) [M1050](/mitre/mitigations/M1050.md) | 20 | 0 | 0 |
| [T1218.001](/mitre/techniques/T1218-001.md) Compiled HTML File | defense-evasion | [M1021](/mitre/mitigations/M1021.md) [M1038](/mitre/mitigations/M1038.md) | 10 | 7 | 0 |
| [T1218.002](/mitre/techniques/T1218-002.md) Control Panel | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) | 11 | 9 | 0 |
| [T1218.003](/mitre/techniques/T1218-003.md) CMSTP | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 15 | 0 |
| [T1218.004](/mitre/techniques/T1218-004.md) InstallUtil | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 0 | 0 |
| [T1218.005](/mitre/techniques/T1218-005.md) Mshta | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 20 | 0 |
| [T1218.007](/mitre/techniques/T1218-007.md) Msiexec | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1042](/mitre/mitigations/M1042.md) | 9 | 0 | 0 |
| [T1218.008](/mitre/techniques/T1218-008.md) Odbcconf | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 0 | 0 |
| [T1218.009](/mitre/techniques/T1218-009.md) Regsvcs/Regasm | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 0 | 0 |
| [T1218.010](/mitre/techniques/T1218-010.md) Regsvr32 | defense-evasion | [M1050](/mitre/mitigations/M1050.md) | 4 | 0 | 0 |
| [T1218.011](/mitre/techniques/T1218-011.md) Rundll32 | defense-evasion | [M1050](/mitre/mitigations/M1050.md) | 4 | 17 | 0 |
| [T1218.012](/mitre/techniques/T1218-012.md) Verclsid | defense-evasion | [M1037](/mitre/mitigations/M1037.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 16 | 0 | 0 |
| [T1218.013](/mitre/techniques/T1218-013.md) Mavinject | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 4 | 0 |
| [T1218.014](/mitre/techniques/T1218-014.md) MMC | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 7 | 0 |
| [T1218.015](/mitre/techniques/T1218-015.md) Electron Applications | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) [M1050](/mitre/mitigations/M1050.md) | 18 | 0 | 0 |
| [T1219](/mitre/techniques/T1219.md) Remote Access Tools | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1034](/mitre/mitigations/M1034.md) [M1037](/mitre/mitigations/M1037.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 13 | 11 | 0 |
| [T1219.001](/mitre/techniques/T1219-001.md) IDE Tunneling | command-and-control | [M1038](/mitre/mitigations/M1038.md) | 0 | 0 | 0 |
| [T1219.002](/mitre/techniques/T1219-002.md) Remote Desktop Software | command-and-control | [M1037](/mitre/mitigations/M1037.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 0 | 0 | 0 |
| [T1219.003](/mitre/techniques/T1219-003.md) Remote Access Hardware | command-and-control | [M1034](/mitre/mitigations/M1034.md) | 0 | 0 | 0 |
| [T1220](/mitre/techniques/T1220.md) XSL Script Processing | defense-evasion | [M1038](/mitre/mitigations/M1038.md) | 6 | 19 | 0 |
| [T1221](/mitre/techniques/T1221.md) Template Injection | defense-evasion | [M1017](/mitre/mitigations/M1017.md) [M1031](/mitre/mitigations/M1031.md) [M1042](/mitre/mitigations/M1042.md) [M1049](/mitre/mitigations/M1049.md) | 14 | 0 | 0 |
| [T1222](/mitre/techniques/T1222.md) File and Directory Permissions Modification | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) | 11 | 4 | 0 |
| [T1222.001](/mitre/techniques/T1222-001.md) Windows File and Directory Permissions Modification | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) | 11 | 0 | 0 |
| [T1222.002](/mitre/techniques/T1222-002.md) Linux and Mac File and Directory Permissions Modification | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) | 11 | 0 | 0 |
| [T1480](/mitre/techniques/T1480.md) Execution Guardrails | defense-evasion | [M1055](/mitre/mitigations/M1055.md) | 0 | 0 | 0 |
| [T1480.001](/mitre/techniques/T1480-001.md) Environmental Keying | defense-evasion | [M1055](/mitre/mitigations/M1055.md) | 0 | 0 | 0 |
| [T1480.002](/mitre/techniques/T1480-002.md) Mutual Exclusion | defense-evasion | [M1055](/mitre/mitigations/M1055.md) | 0 | 0 | 0 |
| [T1482](/mitre/techniques/T1482.md) Domain Trust Discovery | discovery | [M1030](/mitre/mitigations/M1030.md) [M1047](/mitre/mitigations/M1047.md) | 9 | 0 | 0 |
| [T1484](/mitre/techniques/T1484.md) Domain or Tenant Policy Modification | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1047](/mitre/mitigations/M1047.md) | 12 | 4 | 0 |
| [T1484.001](/mitre/techniques/T1484-001.md) Group Policy Modification | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 0 | 0 | 0 |
| [T1484.002](/mitre/techniques/T1484-002.md) Trust Modification | defense-evasion, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) | 0 | 0 | 0 |
| [T1485](/mitre/techniques/T1485.md) Data Destruction | impact | [M1018](/mitre/mitigations/M1018.md) [M1032](/mitre/mitigations/M1032.md) [M1053](/mitre/mitigations/M1053.md) | 10 | 0 | 0 |
| [T1485.001](/mitre/techniques/T1485-001.md) Lifecycle-Triggered Deletion | impact | [M1018](/mitre/mitigations/M1018.md) [M1053](/mitre/mitigations/M1053.md) | 6 | 0 | 0 |
| [T1486](/mitre/techniques/T1486.md) Data Encrypted for Impact | impact | [M1040](/mitre/mitigations/M1040.md) [M1053](/mitre/mitigations/M1053.md) | 11 | 11 | 0 |
| [T1489](/mitre/techniques/T1489.md) Service Stop | impact | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1030](/mitre/mitigations/M1030.md) [M1060](/mitre/mitigations/M1060.md) | 14 | 5 | 0 |
| [T1490](/mitre/techniques/T1490.md) Inhibit System Recovery | impact | [M1018](/mitre/mitigations/M1018.md) [M1028](/mitre/mitigations/M1028.md) [M1038](/mitre/mitigations/M1038.md) [M1053](/mitre/mitigations/M1053.md) | 13 | 6 | 0 |
| [T1491](/mitre/techniques/T1491.md) Defacement | impact | [M1053](/mitre/mitigations/M1053.md) | 10 | 0 | 0 |
| [T1491.001](/mitre/techniques/T1491-001.md) Internal Defacement | impact | [M1053](/mitre/mitigations/M1053.md) | 10 | 0 | 0 |
| [T1491.002](/mitre/techniques/T1491-002.md) External Defacement | impact | [M1053](/mitre/mitigations/M1053.md) | 10 | 2 | 0 |
| [T1495](/mitre/techniques/T1495.md) Firmware Corruption | impact | [M1026](/mitre/mitigations/M1026.md) [M1046](/mitre/mitigations/M1046.md) [M1051](/mitre/mitigations/M1051.md) | 16 | 0 | 0 |
| [T1496](/mitre/techniques/T1496.md) Resource Hijacking | impact | - | 0 | 0 | 0 |
| [T1496.001](/mitre/techniques/T1496-001.md) Compute Hijacking | impact | - | 0 | 0 | 0 |
| [T1496.002](/mitre/techniques/T1496-002.md) Bandwidth Hijacking | impact | - | 0 | 0 | 0 |
| [T1496.003](/mitre/techniques/T1496-003.md) SMS Pumping | impact | [M1013](/mitre/mitigations/M1013.md) | 1 | 0 | 0 |
| [T1496.004](/mitre/techniques/T1496-004.md) Cloud Service Hijacking | impact | - | 0 | 0 | 0 |
| [T1497](/mitre/techniques/T1497.md) Virtualization/Sandbox Evasion | defense-evasion, discovery | - | 0 | 0 | 0 |
| [T1497.001](/mitre/techniques/T1497-001.md) System Checks | defense-evasion, discovery | - | 0 | 0 | 0 |
| [T1497.002](/mitre/techniques/T1497-002.md) User Activity Based Checks | defense-evasion, discovery | - | 0 | 0 | 0 |
| [T1497.003](/mitre/techniques/T1497-003.md) Time Based Checks | defense-evasion, discovery | - | 0 | 6 | 0 |
| [T1498](/mitre/techniques/T1498.md) Network Denial of Service | impact | [M1037](/mitre/mitigations/M1037.md) | 8 | 0 | 0 |
| [T1498.001](/mitre/techniques/T1498-001.md) Direct Network Flood | impact | [M1037](/mitre/mitigations/M1037.md) | 8 | 11 | 0 |
| [T1498.002](/mitre/techniques/T1498-002.md) Reflection Amplification | impact | [M1037](/mitre/mitigations/M1037.md) | 8 | 11 | 0 |
| [T1499](/mitre/techniques/T1499.md) Endpoint Denial of Service | impact | [M1037](/mitre/mitigations/M1037.md) | 9 | 0 | 0 |
| [T1499.001](/mitre/techniques/T1499-001.md) OS Exhaustion Flood | impact | [M1037](/mitre/mitigations/M1037.md) | 9 | 0 | 0 |
| [T1499.002](/mitre/techniques/T1499-002.md) Service Exhaustion Flood | impact | [M1037](/mitre/mitigations/M1037.md) | 9 | 11 | 0 |
| [T1499.003](/mitre/techniques/T1499-003.md) Application Exhaustion Flood | impact | [M1037](/mitre/mitigations/M1037.md) | 9 | 0 | 0 |
| [T1499.004](/mitre/techniques/T1499-004.md) Application or System Exploitation | impact | [M1037](/mitre/mitigations/M1037.md) | 9 | 0 | 0 |
| [T1505](/mitre/techniques/T1505.md) Server Software Component | persistence | [M1018](/mitre/mitigations/M1018.md) [M1024](/mitre/mitigations/M1024.md) [M1026](/mitre/mitigations/M1026.md) [M1042](/mitre/mitigations/M1042.md) [M1045](/mitre/mitigations/M1045.md) [M1046](/mitre/mitigations/M1046.md) +1 | 21 | 0 | 0 |
| [T1505.001](/mitre/techniques/T1505-001.md) SQL Stored Procedures | persistence | [M1026](/mitre/mitigations/M1026.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 12 | 15 | 0 |
| [T1505.002](/mitre/techniques/T1505-002.md) Transport Agent | persistence | [M1026](/mitre/mitigations/M1026.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 21 | 18 | 0 |
| [T1505.003](/mitre/techniques/T1505-003.md) Web Shell ⭐ | persistence | [M1018](/mitre/mitigations/M1018.md) [M1042](/mitre/mitigations/M1042.md) | 8 | 31 | 0 |
| [T1505.004](/mitre/techniques/T1505-004.md) IIS Components | persistence | [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 22 | 4 | 0 |
| [T1505.005](/mitre/techniques/T1505-005.md) Terminal Services DLL | persistence | [M1024](/mitre/mitigations/M1024.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 0 | 0 |
| [T1505.006](/mitre/techniques/T1505-006.md) vSphere Installation Bundles | persistence | [M1045](/mitre/mitigations/M1045.md) [M1046](/mitre/mitigations/M1046.md) [M1047](/mitre/mitigations/M1047.md) | 0 | 0 | 0 |
| [T1518](/mitre/techniques/T1518.md) Software Discovery | discovery | - | 0 | 0 | 0 |
| [T1518.001](/mitre/techniques/T1518-001.md) Security Software Discovery | discovery | - | 0 | 5 | 0 |
| [T1518.002](/mitre/techniques/T1518-002.md) Backup Software Discovery | discovery | - | 0 | 0 | 0 |
| [T1525](/mitre/techniques/T1525.md) Implant Internal Image | persistence | [M1026](/mitre/mitigations/M1026.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 15 | 1 | 0 |
| [T1526](/mitre/techniques/T1526.md) Cloud Service Discovery | discovery | - | 0 | 2 | 0 |
| [T1528](/mitre/techniques/T1528.md) Steal Application Access Token | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1021](/mitre/mitigations/M1021.md) [M1047](/mitre/mitigations/M1047.md) | 19 | 11 | 0 |
| [T1529](/mitre/techniques/T1529.md) System Shutdown/Reboot | impact | - | 0 | 0 | 0 |
| [T1530](/mitre/techniques/T1530.md) Data from Cloud Storage | collection | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1032](/mitre/mitigations/M1032.md) [M1037](/mitre/mitigations/M1037.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) | 32 | 0 | 0 |
| [T1531](/mitre/techniques/T1531.md) Account Access Removal | impact | - | 0 | 7 | 0 |
| [T1534](/mitre/techniques/T1534.md) Internal Spearphishing | lateral-movement | - | 0 | 20 | 0 |
| [T1535](/mitre/techniques/T1535.md) Unused/Unsupported Cloud Regions | defense-evasion | [M1054](/mitre/mitigations/M1054.md) | 1 | 0 | 0 |
| [T1537](/mitre/techniques/T1537.md) Transfer Data to Cloud Account | exfiltration | [M1018](/mitre/mitigations/M1018.md) [M1037](/mitre/mitigations/M1037.md) [M1054](/mitre/mitigations/M1054.md) [M1057](/mitre/mitigations/M1057.md) | 20 | 0 | 0 |
| [T1538](/mitre/techniques/T1538.md) Cloud Service Dashboard | discovery | [M1018](/mitre/mitigations/M1018.md) | 6 | 2 | 0 |
| [T1539](/mitre/techniques/T1539.md) Steal Web Session Cookie | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1021](/mitre/mitigations/M1021.md) [M1032](/mitre/mitigations/M1032.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) [M1054](/mitre/mitigations/M1054.md) | 10 | 9 | 0 |
| [T1542](/mitre/techniques/T1542.md) Pre-OS Boot | defense-evasion, persistence | [M1026](/mitre/mitigations/M1026.md) [M1035](/mitre/mitigations/M1035.md) [M1046](/mitre/mitigations/M1046.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 19 | 0 | 0 |
| [T1542.001](/mitre/techniques/T1542-001.md) System Firmware | persistence, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1046](/mitre/mitigations/M1046.md) [M1051](/mitre/mitigations/M1051.md) | 17 | 8 | 0 |
| [T1542.002](/mitre/techniques/T1542-002.md) Component Firmware | persistence, defense-evasion | [M1051](/mitre/mitigations/M1051.md) | 0 | 7 | 0 |
| [T1542.003](/mitre/techniques/T1542-003.md) Bootkit | persistence, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1046](/mitre/mitigations/M1046.md) | 18 | 5 | 0 |
| [T1542.004](/mitre/techniques/T1542-004.md) ROMMONkit | defense-evasion, persistence | [M1031](/mitre/mitigations/M1031.md) [M1046](/mitre/mitigations/M1046.md) [M1047](/mitre/mitigations/M1047.md) | 19 | 8 | 0 |
| [T1542.005](/mitre/techniques/T1542-005.md) TFTP Boot | defense-evasion, persistence | [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1031](/mitre/mitigations/M1031.md) [M1035](/mitre/mitigations/M1035.md) [M1046](/mitre/mitigations/M1046.md) [M1047](/mitre/mitigations/M1047.md) | 23 | 9 | 0 |
| [T1543](/mitre/techniques/T1543.md) Create or Modify System Process | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1033](/mitre/mitigations/M1033.md) [M1040](/mitre/mitigations/M1040.md) +3 | 20 | 0 | 0 |
| [T1543.001](/mitre/techniques/T1543-001.md) Launch Agent | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 8 | 11 | 0 |
| [T1543.002](/mitre/techniques/T1543-002.md) Systemd Service | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1033](/mitre/mitigations/M1033.md) | 16 | 12 | 0 |
| [T1543.003](/mitre/techniques/T1543-003.md) Windows Service | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1028](/mitre/mitigations/M1028.md) [M1040](/mitre/mitigations/M1040.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 8 | 3 | 0 |
| [T1543.004](/mitre/techniques/T1543-004.md) Launch Daemon | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 8 | 11 | 0 |
| [T1543.005](/mitre/techniques/T1543-005.md) Container Service | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1054](/mitre/mitigations/M1054.md) | 5 | 0 | 0 |
| [T1546](/mitre/techniques/T1546.md) Event Triggered Execution | privilege-escalation, persistence | [M1026](/mitre/mitigations/M1026.md) [M1051](/mitre/mitigations/M1051.md) | 9 | 0 | 0 |
| [T1546.001](/mitre/techniques/T1546-001.md) Change Default File Association | privilege-escalation, persistence | - | 0 | 3 | 0 |
| [T1546.002](/mitre/techniques/T1546-002.md) Screensaver | privilege-escalation, persistence | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 9 | 17 | 0 |
| [T1546.003](/mitre/techniques/T1546-003.md) Windows Management Instrumentation Event Subscription | privilege-escalation, persistence | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1040](/mitre/mitigations/M1040.md) | 12 | 13 | 0 |
| [T1546.004](/mitre/techniques/T1546-004.md) Unix Shell Configuration Modification | privilege-escalation, persistence | [M1022](/mitre/mitigations/M1022.md) | 8 | 12 | 0 |
| [T1546.005](/mitre/techniques/T1546-005.md) Trap | privilege-escalation, persistence | - | 0 | 17 | 0 |
| [T1546.006](/mitre/techniques/T1546-006.md) LC_LOAD_DYLIB Addition | privilege-escalation, persistence | [M1038](/mitre/mitigations/M1038.md) [M1045](/mitre/mitigations/M1045.md) [M1047](/mitre/mitigations/M1047.md) | 13 | 15 | 0 |
| [T1546.007](/mitre/techniques/T1546-007.md) Netsh Helper DLL | privilege-escalation, persistence | - | 0 | 14 | 0 |
| [T1546.008](/mitre/techniques/T1546-008.md) Accessibility Features | privilege-escalation, persistence | [M1028](/mitre/mitigations/M1028.md) [M1035](/mitre/mitigations/M1035.md) [M1038](/mitre/mitigations/M1038.md) | 6 | 28 | 0 |
| [T1546.009](/mitre/techniques/T1546-009.md) AppCert DLLs | privilege-escalation, persistence | [M1038](/mitre/mitigations/M1038.md) | 3 | 19 | 0 |
| [T1546.010](/mitre/techniques/T1546-010.md) AppInit DLLs | privilege-escalation, persistence | [M1038](/mitre/mitigations/M1038.md) [M1051](/mitre/mitigations/M1051.md) | 5 | 19 | 0 |
| [T1546.011](/mitre/techniques/T1546-011.md) Application Shimming | privilege-escalation, persistence | [M1051](/mitre/mitigations/M1051.md) [M1052](/mitre/mitigations/M1052.md) | 2 | 6 | 0 |
| [T1546.012](/mitre/techniques/T1546-012.md) Image File Execution Options Injection | privilege-escalation, persistence | - | 0 | 3 | 0 |
| [T1546.013](/mitre/techniques/T1546-013.md) PowerShell Profile | privilege-escalation, persistence | [M1022](/mitre/mitigations/M1022.md) [M1045](/mitre/mitigations/M1045.md) [M1054](/mitre/mitigations/M1054.md) | 10 | 15 | 0 |
| [T1546.014](/mitre/techniques/T1546-014.md) Emond | privilege-escalation, persistence | [M1042](/mitre/mitigations/M1042.md) | 6 | 13 | 0 |
| [T1546.015](/mitre/techniques/T1546-015.md) Component Object Model Hijacking | privilege-escalation, persistence | - | 0 | 18 | 0 |
| [T1546.016](/mitre/techniques/T1546-016.md) Installer Packages | privilege-escalation, persistence | - | 7 | 0 | 0 |
| [T1546.017](/mitre/techniques/T1546-017.md) Udev Rules | persistence, privilege-escalation | - | 0 | 0 | 0 |
| [T1546.018](/mitre/techniques/T1546-018.md) Python Startup Hooks | persistence, privilege-escalation | - | 0 | 0 | 0 |
| [T1547](/mitre/techniques/T1547.md) Boot or Logon Autostart Execution | persistence, privilege-escalation | - | 0 | 0 | 0 |
| [T1547.001](/mitre/techniques/T1547-001.md) Registry Run Keys / Startup Folder | persistence, privilege-escalation | - | 0 | 18 | 0 |
| [T1547.002](/mitre/techniques/T1547-002.md) Authentication Package | persistence, privilege-escalation | [M1025](/mitre/mitigations/M1025.md) | 5 | 3 | 0 |
| [T1547.003](/mitre/techniques/T1547-003.md) Time Providers | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) | 10 | 3 | 0 |
| [T1547.004](/mitre/techniques/T1547-004.md) Winlogon Helper DLL | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1038](/mitre/mitigations/M1038.md) | 13 | 3 | 0 |
| [T1547.005](/mitre/techniques/T1547-005.md) Security Support Provider | persistence, privilege-escalation | [M1025](/mitre/mitigations/M1025.md) | 5 | 3 | 0 |
| [T1547.006](/mitre/techniques/T1547-006.md) Kernel Modules and Extensions | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) [M1049](/mitre/mitigations/M1049.md) | 18 | 11 | 0 |
| [T1547.007](/mitre/techniques/T1547-007.md) Re-opened Applications | persistence, privilege-escalation | [M1017](/mitre/mitigations/M1017.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 11 | 0 |
| [T1547.008](/mitre/techniques/T1547-008.md) LSASS Driver | persistence, privilege-escalation | [M1025](/mitre/mitigations/M1025.md) [M1043](/mitre/mitigations/M1043.md) [M1044](/mitre/mitigations/M1044.md) | 7 | 15 | 0 |
| [T1547.009](/mitre/techniques/T1547-009.md) Shortcut Modification | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) | 11 | 15 | 0 |
| [T1547.010](/mitre/techniques/T1547-010.md) Port Monitors | persistence, privilege-escalation | - | 0 | 3 | 0 |
| [T1547.012](/mitre/techniques/T1547-012.md) Print Processors | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) | 8 | 0 | 0 |
| [T1547.013](/mitre/techniques/T1547-013.md) XDG Autostart Entries | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1033](/mitre/mitigations/M1033.md) | 15 | 0 | 0 |
| [T1547.014](/mitre/techniques/T1547-014.md) Active Setup | persistence, privilege-escalation | - | 0 | 0 | 0 |
| [T1547.015](/mitre/techniques/T1547-015.md) Login Items | persistence, privilege-escalation | - | 0 | 0 | 0 |
| [T1548](/mitre/techniques/T1548.md) Abuse Elevation Control Mechanism | privilege-escalation, defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) +2 | 22 | 0 | 0 |
| [T1548.001](/mitre/techniques/T1548-001.md) Setuid and Setgid ⭐ | privilege-escalation, defense-evasion | [M1028](/mitre/mitigations/M1028.md) | 3 | 4 | 0 |
| [T1548.002](/mitre/techniques/T1548-002.md) Bypass User Account Control | privilege-escalation, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) [M1052](/mitre/mitigations/M1052.md) | 11 | 21 | 0 |
| [T1548.003](/mitre/techniques/T1548-003.md) Sudo and Sudo Caching ⭐ | privilege-escalation, defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) | 13 | 14 | 0 |
| [T1548.004](/mitre/techniques/T1548-004.md) Elevated Execution with Prompt | privilege-escalation, defense-evasion | [M1038](/mitre/mitigations/M1038.md) | 11 | 5 | 0 |
| [T1548.005](/mitre/techniques/T1548-005.md) Temporary Elevated Cloud Access | privilege-escalation, defense-evasion | [M1018](/mitre/mitigations/M1018.md) | 4 | 10 | 0 |
| [T1548.006](/mitre/techniques/T1548-006.md) TCC Manipulation | defense-evasion, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1047](/mitre/mitigations/M1047.md) | 17 | 0 | 0 |
| [T1550](/mitre/techniques/T1550.md) Use Alternate Authentication Material | defense-evasion, lateral-movement | [M1013](/mitre/mitigations/M1013.md) [M1015](/mitre/mitigations/M1015.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1036](/mitre/mitigations/M1036.md) +1 | 7 | 12 | 0 |
| [T1550.001](/mitre/techniques/T1550-001.md) Application Access Token | defense-evasion, lateral-movement | [M1013](/mitre/mitigations/M1013.md) [M1021](/mitre/mitigations/M1021.md) [M1036](/mitre/mitigations/M1036.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) | 15 | 20 | 0 |
| [T1550.002](/mitre/techniques/T1550-002.md) Pass the Hash | defense-evasion, lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1051](/mitre/mitigations/M1051.md) [M1052](/mitre/mitigations/M1052.md) | 8 | 0 | 0 |
| [T1550.003](/mitre/techniques/T1550-003.md) Pass the Ticket | defense-evasion, lateral-movement | [M1015](/mitre/mitigations/M1015.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) | 11 | 0 | 0 |
| [T1550.004](/mitre/techniques/T1550-004.md) Web Session Cookie | defense-evasion, lateral-movement | [M1054](/mitre/mitigations/M1054.md) | 3 | 18 | 0 |
| [T1552](/mitre/techniques/T1552.md) Unsecured Credentials | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1017](/mitre/mitigations/M1017.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1028](/mitre/mitigations/M1028.md) +5 | 32 | 9 | 0 |
| [T1552.001](/mitre/techniques/T1552-001.md) Credentials In Files ⭐ | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1022](/mitre/mitigations/M1022.md) [M1027](/mitre/mitigations/M1027.md) [M1047](/mitre/mitigations/M1047.md) | 17 | 11 | 0 |
| [T1552.002](/mitre/techniques/T1552-002.md) Credentials in Registry | credential-access | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1047](/mitre/mitigations/M1047.md) | 18 | 3 | 0 |
| [T1552.003](/mitre/techniques/T1552-003.md) Shell History | credential-access | [M1028](/mitre/mitigations/M1028.md) | 4 | 11 | 0 |
| [T1552.004](/mitre/techniques/T1552-004.md) Private Keys | credential-access | [M1022](/mitre/mitigations/M1022.md) [M1027](/mitre/mitigations/M1027.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) | 21 | 0 | 0 |
| [T1552.005](/mitre/techniques/T1552-005.md) Cloud Instance Metadata API | credential-access | [M1035](/mitre/mitigations/M1035.md) [M1037](/mitre/mitigations/M1037.md) [M1042](/mitre/mitigations/M1042.md) | 14 | 2 | 0 |
| [T1552.006](/mitre/techniques/T1552-006.md) Group Policy Preferences | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 12 | 4 | 0 |
| [T1552.007](/mitre/techniques/T1552-007.md) Container API | credential-access | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1035](/mitre/mitigations/M1035.md) | 14 | 0 | 0 |
| [T1552.008](/mitre/techniques/T1552-008.md) Chat Messages | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1047](/mitre/mitigations/M1047.md) | 2 | 0 | 0 |
| [T1553](/mitre/techniques/T1553.md) Subvert Trust Controls | defense-evasion | [M1024](/mitre/mitigations/M1024.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1038](/mitre/mitigations/M1038.md) [M1054](/mitre/mitigations/M1054.md) | 20 | 0 | 0 |
| [T1553.001](/mitre/techniques/T1553-001.md) Gatekeeper Bypass | defense-evasion | [M1038](/mitre/mitigations/M1038.md) | 6 | 0 | 0 |
| [T1553.002](/mitre/techniques/T1553-002.md) Code Signing | defense-evasion | - | 0 | 0 | 0 |
| [T1553.003](/mitre/techniques/T1553-003.md) SIP and Trust Provider Hijacking | defense-evasion | [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1038](/mitre/mitigations/M1038.md) | 10 | 3 | 0 |
| [T1553.004](/mitre/techniques/T1553-004.md) Install Root Certificate | defense-evasion | [M1028](/mitre/mitigations/M1028.md) [M1054](/mitre/mitigations/M1054.md) | 6 | 0 | 0 |
| [T1553.005](/mitre/techniques/T1553-005.md) Mark-of-the-Web Bypass | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 6 | 0 | 0 |
| [T1553.006](/mitre/techniques/T1553-006.md) Code Signing Policy Modification | defense-evasion | [M1024](/mitre/mitigations/M1024.md) [M1026](/mitre/mitigations/M1026.md) [M1046](/mitre/mitigations/M1046.md) | 13 | 0 | 0 |
| [T1554](/mitre/techniques/T1554.md) Compromise Host Software Binary | persistence | [M1045](/mitre/mitigations/M1045.md) | 9 | 4 | 0 |
| [T1555](/mitre/techniques/T1555.md) Credentials from Password Stores | credential-access | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1051](/mitre/mitigations/M1051.md) | 8 | 13 | 0 |
| [T1555.001](/mitre/techniques/T1555-001.md) Keychain | credential-access | [M1027](/mitre/mitigations/M1027.md) | 3 | 2 | 0 |
| [T1555.002](/mitre/techniques/T1555-002.md) Securityd Memory | credential-access | - | 5 | 2 | 0 |
| [T1555.003](/mitre/techniques/T1555-003.md) Credentials from Web Browsers | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1021](/mitre/mitigations/M1021.md) [M1027](/mitre/mitigations/M1027.md) [M1051](/mitre/mitigations/M1051.md) | 0 | 15 | 0 |
| [T1555.004](/mitre/techniques/T1555-004.md) Windows Credential Manager | credential-access | [M1042](/mitre/mitigations/M1042.md) | 5 | 0 | 0 |
| [T1555.005](/mitre/techniques/T1555-005.md) Password Managers | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1027](/mitre/mitigations/M1027.md) [M1051](/mitre/mitigations/M1051.md) [M1054](/mitre/mitigations/M1054.md) | 8 | 0 | 0 |
| [T1555.006](/mitre/techniques/T1555-006.md) Cloud Secrets Management Stores | credential-access | [M1026](/mitre/mitigations/M1026.md) | 4 | 0 | 0 |
| [T1556](/mitre/techniques/T1556.md) Modify Authentication Process | credential-access, defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1025](/mitre/mitigations/M1025.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) +3 | 17 | 12 | 0 |
| [T1556.001](/mitre/techniques/T1556-001.md) Domain Controller Authentication | credential-access, defense-evasion | [M1017](/mitre/mitigations/M1017.md) [M1025](/mitre/mitigations/M1025.md) [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) | 14 | 0 | 0 |
| [T1556.002](/mitre/techniques/T1556-002.md) Password Filter DLL | credential-access, defense-evasion | [M1028](/mitre/mitigations/M1028.md) | 3 | 13 | 0 |
| [T1556.003](/mitre/techniques/T1556-003.md) Pluggable Authentication Modules | credential-access, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) | 12 | 12 | 0 |
| [T1556.004](/mitre/techniques/T1556-004.md) Network Device Authentication | credential-access, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) | 13 | 0 | 0 |
| [T1556.005](/mitre/techniques/T1556-005.md) Reversible Encryption | credential-access, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) | 4 | 0 | 0 |
| [T1556.006](/mitre/techniques/T1556-006.md) Multi-Factor Authentication | credential-access, defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1032](/mitre/mitigations/M1032.md) [M1047](/mitre/mitigations/M1047.md) | 6 | 0 | 0 |
| [T1556.007](/mitre/techniques/T1556-007.md) Hybrid Identity | credential-access, defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1032](/mitre/mitigations/M1032.md) [M1047](/mitre/mitigations/M1047.md) | 6 | 0 | 0 |
| [T1556.008](/mitre/techniques/T1556-008.md) Network Provider DLL | credential-access, defense-evasion | [M1024](/mitre/mitigations/M1024.md) [M1028](/mitre/mitigations/M1028.md) [M1047](/mitre/mitigations/M1047.md) | 9 | 0 | 0 |
| [T1556.009](/mitre/techniques/T1556-009.md) Conditional Access Policies | credential-access, defense-evasion | [M1018](/mitre/mitigations/M1018.md) | 14 | 4 | 0 |
| [T1557](/mitre/techniques/T1557.md) Adversary-in-the-Middle | credential-access, collection | [M1017](/mitre/mitigations/M1017.md) [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1035](/mitre/mitigations/M1035.md) [M1037](/mitre/mitigations/M1037.md) [M1041](/mitre/mitigations/M1041.md) +1 | 24 | 9 | 0 |
| [T1557.001](/mitre/techniques/T1557-001.md) LLMNR/NBT-NS Poisoning and SMB Relay | credential-access, collection | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1042](/mitre/mitigations/M1042.md) | 15 | 10 | 0 |
| [T1557.002](/mitre/techniques/T1557-002.md) ARP Cache Poisoning | credential-access, collection | [M1017](/mitre/mitigations/M1017.md) [M1031](/mitre/mitigations/M1031.md) [M1035](/mitre/mitigations/M1035.md) [M1037](/mitre/mitigations/M1037.md) [M1041](/mitre/mitigations/M1041.md) [M1042](/mitre/mitigations/M1042.md) | 22 | 0 | 0 |
| [T1557.003](/mitre/techniques/T1557-003.md) DHCP Spoofing | credential-access, collection | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 15 | 9 | 0 |
| [T1557.004](/mitre/techniques/T1557-004.md) Evil Twin | credential-access, collection | [M1017](/mitre/mitigations/M1017.md) [M1031](/mitre/mitigations/M1031.md) | 16 | 0 | 0 |
| [T1558](/mitre/techniques/T1558.md) Steal or Forge Kerberos Tickets | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1041](/mitre/mitigations/M1041.md) [M1043](/mitre/mitigations/M1043.md) [M1047](/mitre/mitigations/M1047.md) | 19 | 11 | 0 |
| [T1558.001](/mitre/techniques/T1558-001.md) Golden Ticket | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1026](/mitre/mitigations/M1026.md) | 9 | 11 | 0 |
| [T1558.002](/mitre/techniques/T1558-002.md) Silver Ticket | credential-access | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1041](/mitre/mitigations/M1041.md) | 19 | 0 | 0 |
| [T1558.003](/mitre/techniques/T1558-003.md) Kerberoasting ⭐ | credential-access | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1041](/mitre/mitigations/M1041.md) | 19 | 10 | 0 |
| [T1558.004](/mitre/techniques/T1558-004.md) AS-REP Roasting | credential-access | [M1027](/mitre/mitigations/M1027.md) [M1041](/mitre/mitigations/M1041.md) [M1047](/mitre/mitigations/M1047.md) | 19 | 0 | 0 |
| [T1558.005](/mitre/techniques/T1558-005.md) Ccache Files | credential-access | [M1043](/mitre/mitigations/M1043.md) [M1047](/mitre/mitigations/M1047.md) | 10 | 0 | 0 |
| [T1559](/mitre/techniques/T1559.md) Inter-Process Communication | execution | [M1013](/mitre/mitigations/M1013.md) [M1026](/mitre/mitigations/M1026.md) [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) [M1048](/mitre/mitigations/M1048.md) [M1054](/mitre/mitigations/M1054.md) | 19 | 0 | 0 |
| [T1559.001](/mitre/techniques/T1559-001.md) Component Object Model | execution | [M1026](/mitre/mitigations/M1026.md) [M1048](/mitre/mitigations/M1048.md) | 13 | 0 | 0 |
| [T1559.002](/mitre/techniques/T1559-002.md) Dynamic Data Exchange | execution | [M1040](/mitre/mitigations/M1040.md) [M1042](/mitre/mitigations/M1042.md) [M1048](/mitre/mitigations/M1048.md) [M1054](/mitre/mitigations/M1054.md) | 14 | 0 | 0 |
| [T1559.003](/mitre/techniques/T1559-003.md) XPC Services | execution | [M1013](/mitre/mitigations/M1013.md) | 7 | 0 | 0 |
| [T1560](/mitre/techniques/T1560.md) Archive Collected Data | collection | [M1047](/mitre/mitigations/M1047.md) | 5 | 11 | 0 |
| [T1560.001](/mitre/techniques/T1560-001.md) Archive via Utility | collection | [M1047](/mitre/mitigations/M1047.md) | 5 | 11 | 0 |
| [T1560.002](/mitre/techniques/T1560-002.md) Archive via Library | collection | - | 0 | 11 | 0 |
| [T1560.003](/mitre/techniques/T1560-003.md) Archive via Custom Method | collection | - | 0 | 11 | 0 |
| [T1561](/mitre/techniques/T1561.md) Disk Wipe | impact | [M1053](/mitre/mitigations/M1053.md) | 10 | 0 | 0 |
| [T1561.001](/mitre/techniques/T1561-001.md) Disk Content Wipe | impact | [M1053](/mitre/mitigations/M1053.md) | 10 | 1 | 0 |
| [T1561.002](/mitre/techniques/T1561-002.md) Disk Structure Wipe | impact | [M1053](/mitre/mitigations/M1053.md) | 10 | 1 | 0 |
| [T1562](/mitre/techniques/T1562.md) Impair Defenses | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) +1 | 16 | 0 | 0 |
| [T1562.001](/mitre/techniques/T1562-001.md) Disable or Modify Tools | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) | 13 | 12 | 0 |
| [T1562.002](/mitre/techniques/T1562-002.md) Disable Windows Event Logging | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1047](/mitre/mitigations/M1047.md) | 13 | 4 | 0 |
| [T1562.003](/mitre/techniques/T1562-003.md) Impair Command History Logging | defense-evasion | [M1028](/mitre/mitigations/M1028.md) [M1039](/mitre/mitigations/M1039.md) | 4 | 20 | 0 |
| [T1562.004](/mitre/techniques/T1562-004.md) Disable or Modify System Firewall | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1047](/mitre/mitigations/M1047.md) | 13 | 2 | 0 |
| [T1562.006](/mitre/techniques/T1562-006.md) Indicator Blocking | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1054](/mitre/mitigations/M1054.md) | 17 | 0 | 0 |
| [T1562.007](/mitre/techniques/T1562-007.md) Disable or Modify Cloud Firewall | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 6 | 2 | 0 |
| [T1562.008](/mitre/techniques/T1562-008.md) Disable or Modify Cloud Logs | defense-evasion | [M1018](/mitre/mitigations/M1018.md) | 7 | 2 | 0 |
| [T1562.009](/mitre/techniques/T1562-009.md) Safe Mode Boot | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1054](/mitre/mitigations/M1054.md) | 13 | 4 | 0 |
| [T1562.010](/mitre/techniques/T1562-010.md) Downgrade Attack | defense-evasion | [M1042](/mitre/mitigations/M1042.md) [M1054](/mitre/mitigations/M1054.md) | 7 | 1 | 0 |
| [T1562.011](/mitre/techniques/T1562-011.md) Spoof Security Alerting | defense-evasion | [M1038](/mitre/mitigations/M1038.md) | 5 | 0 | 0 |
| [T1562.012](/mitre/techniques/T1562-012.md) Disable or Modify Linux Audit System | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 8 | 0 | 0 |
| [T1562.013](/mitre/techniques/T1562-013.md) Disable or Modify Network Device Firewall | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 0 | 4 | 0 |
| [T1563](/mitre/techniques/T1563.md) Remote Service Session Hijacking | lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1030](/mitre/mitigations/M1030.md) [M1042](/mitre/mitigations/M1042.md) | 19 | 10 | 0 |
| [T1563.001](/mitre/techniques/T1563-001.md) SSH Hijacking | lateral-movement | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1042](/mitre/mitigations/M1042.md) | 17 | 1 | 0 |
| [T1563.002](/mitre/techniques/T1563-002.md) RDP Hijacking | lateral-movement | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1028](/mitre/mitigations/M1028.md) [M1030](/mitre/mitigations/M1030.md) [M1035](/mitre/mitigations/M1035.md) [M1042](/mitre/mitigations/M1042.md) +1 | 18 | 1 | 0 |
| [T1564](/mitre/techniques/T1564.md) Hide Artifacts | defense-evasion | [M1013](/mitre/mitigations/M1013.md) [M1033](/mitre/mitigations/M1033.md) [M1047](/mitre/mitigations/M1047.md) [M1049](/mitre/mitigations/M1049.md) | 0 | 0 | 0 |
| [T1564.001](/mitre/techniques/T1564-001.md) Hidden Files and Directories | defense-evasion | - | 0 | 0 | 0 |
| [T1564.002](/mitre/techniques/T1564-002.md) Hidden Users | defense-evasion | [M1028](/mitre/mitigations/M1028.md) | 3 | 12 | 0 |
| [T1564.003](/mitre/techniques/T1564-003.md) Hidden Window | defense-evasion | [M1033](/mitre/mitigations/M1033.md) [M1038](/mitre/mitigations/M1038.md) | 3 | 14 | 0 |
| [T1564.004](/mitre/techniques/T1564-004.md) NTFS File Attributes | defense-evasion | [M1022](/mitre/mitigations/M1022.md) | 6 | 0 | 0 |
| [T1564.005](/mitre/techniques/T1564-005.md) Hidden File System | defense-evasion | - | 0 | 4 | 0 |
| [T1564.006](/mitre/techniques/T1564-006.md) Run Virtual Instance | defense-evasion | [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) | 7 | 16 | 0 |
| [T1564.007](/mitre/techniques/T1564-007.md) VBA Stomping | defense-evasion | [M1042](/mitre/mitigations/M1042.md) | 4 | 14 | 0 |
| [T1564.008](/mitre/techniques/T1564-008.md) Email Hiding Rules | defense-evasion | [M1047](/mitre/mitigations/M1047.md) | 7 | 4 | 0 |
| [T1564.009](/mitre/techniques/T1564-009.md) Resource Forking | defense-evasion | [M1013](/mitre/mitigations/M1013.md) | 13 | 1 | 0 |
| [T1564.010](/mitre/techniques/T1564-010.md) Process Argument Spoofing | defense-evasion | - | 3 | 0 | 0 |
| [T1564.011](/mitre/techniques/T1564-011.md) Ignore Process Interrupts | defense-evasion | - | 0 | 0 | 0 |
| [T1564.012](/mitre/techniques/T1564-012.md) File/Path Exclusions | defense-evasion | [M1013](/mitre/mitigations/M1013.md) [M1049](/mitre/mitigations/M1049.md) | 1 | 0 | 0 |
| [T1564.013](/mitre/techniques/T1564-013.md) Bind Mounts | defense-evasion | - | 0 | 0 | 0 |
| [T1564.014](/mitre/techniques/T1564-014.md) Extended Attributes | defense-evasion | [M1040](/mitre/mitigations/M1040.md) | 0 | 0 | 0 |
| [T1565](/mitre/techniques/T1565.md) Data Manipulation | impact | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1030](/mitre/mitigations/M1030.md) [M1041](/mitre/mitigations/M1041.md) | 26 | 0 | 0 |
| [T1565.001](/mitre/techniques/T1565-001.md) Stored Data Manipulation | impact | [M1022](/mitre/mitigations/M1022.md) [M1029](/mitre/mitigations/M1029.md) [M1041](/mitre/mitigations/M1041.md) | 23 | 11 | 0 |
| [T1565.002](/mitre/techniques/T1565-002.md) Transmitted Data Manipulation | impact | [M1041](/mitre/mitigations/M1041.md) | 12 | 9 | 0 |
| [T1565.003](/mitre/techniques/T1565-003.md) Runtime Data Manipulation | impact | [M1022](/mitre/mitigations/M1022.md) [M1030](/mitre/mitigations/M1030.md) | 13 | 15 | 0 |
| [T1566](/mitre/techniques/T1566.md) Phishing | initial-access | [M1017](/mitre/mitigations/M1017.md) [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) [M1047](/mitre/mitigations/M1047.md) [M1049](/mitre/mitigations/M1049.md) [M1054](/mitre/mitigations/M1054.md) | 13 | 0 | 0 |
| [T1566.001](/mitre/techniques/T1566-001.md) Spearphishing Attachment | initial-access | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) [M1047](/mitre/mitigations/M1047.md) [M1049](/mitre/mitigations/M1049.md) +1 | 12 | 31 | 0 |
| [T1566.002](/mitre/techniques/T1566-002.md) Spearphishing Link | initial-access | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1021](/mitre/mitigations/M1021.md) [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) | 11 | 34 | 0 |
| [T1566.003](/mitre/techniques/T1566-003.md) Spearphishing via Service | initial-access | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) [M1021](/mitre/mitigations/M1021.md) [M1047](/mitre/mitigations/M1047.md) [M1049](/mitre/mitigations/M1049.md) | 10 | 15 | 0 |
| [T1566.004](/mitre/techniques/T1566-004.md) Spearphishing Voice | initial-access | [M1017](/mitre/mitigations/M1017.md) | 0 | 0 | 0 |
| [T1567](/mitre/techniques/T1567.md) Exfiltration Over Web Service | exfiltration | [M1021](/mitre/mitigations/M1021.md) [M1057](/mitre/mitigations/M1057.md) | 17 | 11 | 0 |
| [T1567.001](/mitre/techniques/T1567-001.md) Exfiltration to Code Repository | exfiltration | [M1021](/mitre/mitigations/M1021.md) | 3 | 11 | 0 |
| [T1567.002](/mitre/techniques/T1567-002.md) Exfiltration to Cloud Storage | exfiltration | [M1021](/mitre/mitigations/M1021.md) | 3 | 11 | 0 |
| [T1567.003](/mitre/techniques/T1567-003.md) Exfiltration to Text Storage Sites | exfiltration | [M1021](/mitre/mitigations/M1021.md) | 3 | 0 | 0 |
| [T1567.004](/mitre/techniques/T1567-004.md) Exfiltration Over Webhook | exfiltration | [M1057](/mitre/mitigations/M1057.md) | 3 | 0 | 0 |
| [T1568](/mitre/techniques/T1568.md) Dynamic Resolution | command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 16 | 0 |
| [T1568.001](/mitre/techniques/T1568-001.md) Fast Flux DNS | command-and-control | - | 0 | 0 | 0 |
| [T1568.002](/mitre/techniques/T1568-002.md) Domain Generation Algorithms | command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 0 | 0 |
| [T1568.003](/mitre/techniques/T1568-003.md) DNS Calculation | command-and-control | - | 0 | 0 | 0 |
| [T1569](/mitre/techniques/T1569.md) System Services | execution | [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1040](/mitre/mitigations/M1040.md) | 14 | 0 | 0 |
| [T1569.001](/mitre/techniques/T1569-001.md) Launchctl | execution | [M1018](/mitre/mitigations/M1018.md) | 7 | 0 | 0 |
| [T1569.002](/mitre/techniques/T1569-002.md) Service Execution | execution | [M1022](/mitre/mitigations/M1022.md) [M1026](/mitre/mitigations/M1026.md) [M1040](/mitre/mitigations/M1040.md) | 13 | 0 | 0 |
| [T1569.003](/mitre/techniques/T1569-003.md) Systemctl | execution | [M1018](/mitre/mitigations/M1018.md) | 0 | 0 | 0 |
| [T1570](/mitre/techniques/T1570.md) Lateral Tool Transfer | lateral-movement | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 11 | 11 | 0 |
| [T1571](/mitre/techniques/T1571.md) Non-Standard Port | command-and-control | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) | 8 | 11 | 0 |
| [T1572](/mitre/techniques/T1572.md) Protocol Tunneling ⭐ | command-and-control | [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) | 11 | 11 | 0 |
| [T1573](/mitre/techniques/T1573.md) Encrypted Channel | command-and-control | [M1020](/mitre/mitigations/M1020.md) [M1031](/mitre/mitigations/M1031.md) | 11 | 11 | 0 |
| [T1573.001](/mitre/techniques/T1573-001.md) Symmetric Cryptography | command-and-control | [M1031](/mitre/mitigations/M1031.md) | 11 | 11 | 0 |
| [T1573.002](/mitre/techniques/T1573-002.md) Asymmetric Cryptography | command-and-control | [M1020](/mitre/mitigations/M1020.md) [M1031](/mitre/mitigations/M1031.md) | 11 | 23 | 0 |
| [T1574](/mitre/techniques/T1574.md) Hijack Execution Flow ⭐ | persistence, privilege-escalation | [M1013](/mitre/mitigations/M1013.md) [M1018](/mitre/mitigations/M1018.md) [M1022](/mitre/mitigations/M1022.md) [M1024](/mitre/mitigations/M1024.md) [M1038](/mitre/mitigations/M1038.md) [M1040](/mitre/mitigations/M1040.md) +4 | 18 | 0 | 0 |
| [T1574.001](/mitre/techniques/T1574-001.md) DLL | persistence, privilege-escalation | [M1013](/mitre/mitigations/M1013.md) [M1038](/mitre/mitigations/M1038.md) [M1044](/mitre/mitigations/M1044.md) [M1047](/mitre/mitigations/M1047.md) [M1051](/mitre/mitigations/M1051.md) | 8 | 11 | 0 |
| [T1574.004](/mitre/techniques/T1574-004.md) Dylib Hijacking | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 13 | 11 | 0 |
| [T1574.005](/mitre/techniques/T1574-005.md) Executable Installer File Permissions Weakness | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) [M1052](/mitre/mitigations/M1052.md) | 11 | 5 | 0 |
| [T1574.006](/mitre/techniques/T1574-006.md) Dynamic Linker Hijacking | persistence, privilege-escalation | [M1028](/mitre/mitigations/M1028.md) [M1038](/mitre/mitigations/M1038.md) | 4 | 12 | 0 |
| [T1574.007](/mitre/techniques/T1574-007.md) Path Interception by PATH Environment Variable | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) | 15 | 15 | 0 |
| [T1574.008](/mitre/techniques/T1574-008.md) Path Interception by Search Order Hijacking | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) | 15 | 15 | 0 |
| [T1574.009](/mitre/techniques/T1574-009.md) Path Interception by Unquoted Path | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) [M1038](/mitre/mitigations/M1038.md) [M1047](/mitre/mitigations/M1047.md) | 15 | 15 | 0 |
| [T1574.010](/mitre/techniques/T1574-010.md) Services File Permissions Weakness | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) [M1052](/mitre/mitigations/M1052.md) | 11 | 5 | 0 |
| [T1574.011](/mitre/techniques/T1574-011.md) Services Registry Permissions Weakness | persistence, privilege-escalation | [M1024](/mitre/mitigations/M1024.md) | 2 | 4 | 0 |
| [T1574.012](/mitre/techniques/T1574-012.md) COR_PROFILER | persistence, privilege-escalation | [M1018](/mitre/mitigations/M1018.md) [M1024](/mitre/mitigations/M1024.md) [M1038](/mitre/mitigations/M1038.md) | 9 | 13 | 0 |
| [T1574.013](/mitre/techniques/T1574-013.md) KernelCallbackTable | persistence, privilege-escalation | [M1040](/mitre/mitigations/M1040.md) | 7 | 0 | 0 |
| [T1574.014](/mitre/techniques/T1574-014.md) AppDomainManager | persistence, privilege-escalation | [M1022](/mitre/mitigations/M1022.md) | 10 | 0 | 0 |
| [T1578](/mitre/techniques/T1578.md) Modify Cloud Compute Infrastructure | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 0 | 0 |
| [T1578.001](/mitre/techniques/T1578-001.md) Create Snapshot | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 0 | 0 |
| [T1578.002](/mitre/techniques/T1578-002.md) Create Cloud Instance | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 7 | 0 |
| [T1578.003](/mitre/techniques/T1578-003.md) Delete Cloud Instance | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 7 | 0 |
| [T1578.004](/mitre/techniques/T1578-004.md) Revert Cloud Instance | defense-evasion | - | 0 | 7 | 0 |
| [T1578.005](/mitre/techniques/T1578-005.md) Modify Cloud Compute Configurations | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) | 5 | 2 | 0 |
| [T1580](/mitre/techniques/T1580.md) Cloud Infrastructure Discovery | discovery | [M1018](/mitre/mitigations/M1018.md) | 5 | 0 | 0 |
| [T1583](/mitre/techniques/T1583.md) Acquire Infrastructure | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.001](/mitre/techniques/T1583-001.md) Domains | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.002](/mitre/techniques/T1583-002.md) DNS Server | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.003](/mitre/techniques/T1583-003.md) Virtual Private Server | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.004](/mitre/techniques/T1583-004.md) Server | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.005](/mitre/techniques/T1583-005.md) Botnet | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.006](/mitre/techniques/T1583-006.md) Web Services | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.007](/mitre/techniques/T1583-007.md) Serverless | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1583.008](/mitre/techniques/T1583-008.md) Malvertising | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584](/mitre/techniques/T1584.md) Compromise Infrastructure | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.001](/mitre/techniques/T1584-001.md) Domains | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.002](/mitre/techniques/T1584-002.md) DNS Server | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.003](/mitre/techniques/T1584-003.md) Virtual Private Server | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.004](/mitre/techniques/T1584-004.md) Server | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.005](/mitre/techniques/T1584-005.md) Botnet | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.006](/mitre/techniques/T1584-006.md) Web Services | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.007](/mitre/techniques/T1584-007.md) Serverless | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1584.008](/mitre/techniques/T1584-008.md) Network Devices | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1585](/mitre/techniques/T1585.md) Establish Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1585.001](/mitre/techniques/T1585-001.md) Social Media Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1585.002](/mitre/techniques/T1585-002.md) Email Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1585.003](/mitre/techniques/T1585-003.md) Cloud Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1586](/mitre/techniques/T1586.md) Compromise Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1586.001](/mitre/techniques/T1586-001.md) Social Media Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1586.002](/mitre/techniques/T1586-002.md) Email Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1586.003](/mitre/techniques/T1586-003.md) Cloud Accounts | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1587](/mitre/techniques/T1587.md) Develop Capabilities | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1587.001](/mitre/techniques/T1587-001.md) Malware | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1587.002](/mitre/techniques/T1587-002.md) Code Signing Certificates | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1587.003](/mitre/techniques/T1587-003.md) Digital Certificates | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1587.004](/mitre/techniques/T1587-004.md) Exploits | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588](/mitre/techniques/T1588.md) Obtain Capabilities | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.001](/mitre/techniques/T1588-001.md) Malware | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.002](/mitre/techniques/T1588-002.md) Tool | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.003](/mitre/techniques/T1588-003.md) Code Signing Certificates | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.004](/mitre/techniques/T1588-004.md) Digital Certificates | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.005](/mitre/techniques/T1588-005.md) Exploits | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.006](/mitre/techniques/T1588-006.md) Vulnerabilities | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1588.007](/mitre/techniques/T1588-007.md) Artificial Intelligence | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1589](/mitre/techniques/T1589.md) Gather Victim Identity Information | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1589.001](/mitre/techniques/T1589-001.md) Credentials | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1589.002](/mitre/techniques/T1589-002.md) Email Addresses | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1589.003](/mitre/techniques/T1589-003.md) Employee Names | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1590](/mitre/techniques/T1590.md) Gather Victim Network Information | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1590.001](/mitre/techniques/T1590-001.md) Domain Properties | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1590.002](/mitre/techniques/T1590-002.md) DNS | reconnaissance | [M1054](/mitre/mitigations/M1054.md) | 5 | 0 | 0 |
| [T1590.003](/mitre/techniques/T1590-003.md) Network Trust Dependencies | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1590.004](/mitre/techniques/T1590-004.md) Network Topology | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1590.005](/mitre/techniques/T1590-005.md) IP Addresses | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1590.006](/mitre/techniques/T1590-006.md) Network Security Appliances | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1591](/mitre/techniques/T1591.md) Gather Victim Org Information | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1591.001](/mitre/techniques/T1591-001.md) Determine Physical Locations | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1591.002](/mitre/techniques/T1591-002.md) Business Relationships | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1591.003](/mitre/techniques/T1591-003.md) Identify Business Tempo | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1591.004](/mitre/techniques/T1591-004.md) Identify Roles | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1592](/mitre/techniques/T1592.md) Gather Victim Host Information | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1592.001](/mitre/techniques/T1592-001.md) Hardware | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1592.002](/mitre/techniques/T1592-002.md) Software | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1592.003](/mitre/techniques/T1592-003.md) Firmware | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1592.004](/mitre/techniques/T1592-004.md) Client Configurations | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1593](/mitre/techniques/T1593.md) Search Open Websites/Domains | reconnaissance | [M1013](/mitre/mitigations/M1013.md) [M1047](/mitre/mitigations/M1047.md) | 0 | 0 | 0 |
| [T1593.001](/mitre/techniques/T1593-001.md) Social Media | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1593.002](/mitre/techniques/T1593-002.md) Search Engines | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1593.003](/mitre/techniques/T1593-003.md) Code Repositories | reconnaissance | [M1013](/mitre/mitigations/M1013.md) [M1047](/mitre/mitigations/M1047.md) | 1 | 0 | 0 |
| [T1594](/mitre/techniques/T1594.md) Search Victim-Owned Websites | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1595](/mitre/techniques/T1595.md) Active Scanning | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1595.001](/mitre/techniques/T1595-001.md) Scanning IP Blocks | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1595.002](/mitre/techniques/T1595-002.md) Vulnerability Scanning | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1595.003](/mitre/techniques/T1595-003.md) Wordlist Scanning | reconnaissance | [M1042](/mitre/mitigations/M1042.md) [M1056](/mitre/mitigations/M1056.md) | 1 | 0 | 0 |
| [T1596](/mitre/techniques/T1596.md) Search Open Technical Databases | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1596.001](/mitre/techniques/T1596-001.md) DNS/Passive DNS | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1596.002](/mitre/techniques/T1596-002.md) WHOIS | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1596.003](/mitre/techniques/T1596-003.md) Digital Certificates | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1596.004](/mitre/techniques/T1596-004.md) CDNs | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1596.005](/mitre/techniques/T1596-005.md) Scan Databases | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1597](/mitre/techniques/T1597.md) Search Closed Sources | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1597.001](/mitre/techniques/T1597-001.md) Threat Intel Vendors | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1597.002](/mitre/techniques/T1597-002.md) Purchase Technical Data | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1598](/mitre/techniques/T1598.md) Phishing for Information | reconnaissance | [M1017](/mitre/mitigations/M1017.md) [M1054](/mitre/mitigations/M1054.md) | 11 | 0 | 0 |
| [T1598.001](/mitre/techniques/T1598-001.md) Spearphishing Service | reconnaissance | [M1017](/mitre/mitigations/M1017.md) | 7 | 0 | 0 |
| [T1598.002](/mitre/techniques/T1598-002.md) Spearphishing Attachment | reconnaissance | [M1017](/mitre/mitigations/M1017.md) [M1054](/mitre/mitigations/M1054.md) | 11 | 0 | 0 |
| [T1598.003](/mitre/techniques/T1598-003.md) Spearphishing Link | reconnaissance | [M1017](/mitre/mitigations/M1017.md) [M1054](/mitre/mitigations/M1054.md) | 11 | 0 | 0 |
| [T1598.004](/mitre/techniques/T1598-004.md) Spearphishing Voice | reconnaissance | [M1017](/mitre/mitigations/M1017.md) | 0 | 0 | 0 |
| [T1599](/mitre/techniques/T1599.md) Network Boundary Bridging | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1037](/mitre/mitigations/M1037.md) [M1043](/mitre/mitigations/M1043.md) | 18 | 0 | 0 |
| [T1599.001](/mitre/techniques/T1599-001.md) Network Address Translation Traversal | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1037](/mitre/mitigations/M1037.md) [M1043](/mitre/mitigations/M1043.md) | 18 | 0 | 0 |
| [T1600](/mitre/techniques/T1600.md) Weaken Encryption | defense-evasion | - | 0 | 0 | 0 |
| [T1600.001](/mitre/techniques/T1600-001.md) Reduce Key Space | defense-evasion | - | 0 | 0 | 0 |
| [T1600.002](/mitre/techniques/T1600-002.md) Disable Crypto Hardware | defense-evasion | - | 0 | 0 | 0 |
| [T1601](/mitre/techniques/T1601.md) Modify System Image | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1043](/mitre/mitigations/M1043.md) [M1045](/mitre/mitigations/M1045.md) [M1046](/mitre/mitigations/M1046.md) | 24 | 0 | 0 |
| [T1601.001](/mitre/techniques/T1601-001.md) Patch System Image | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1043](/mitre/mitigations/M1043.md) [M1045](/mitre/mitigations/M1045.md) [M1046](/mitre/mitigations/M1046.md) | 24 | 0 | 0 |
| [T1601.002](/mitre/techniques/T1601-002.md) Downgrade System Image | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1027](/mitre/mitigations/M1027.md) [M1032](/mitre/mitigations/M1032.md) [M1043](/mitre/mitigations/M1043.md) [M1045](/mitre/mitigations/M1045.md) [M1046](/mitre/mitigations/M1046.md) | 24 | 0 | 0 |
| [T1602](/mitre/techniques/T1602.md) Data from Configuration Repository | collection | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1041](/mitre/mitigations/M1041.md) [M1051](/mitre/mitigations/M1051.md) [M1054](/mitre/mitigations/M1054.md) | 25 | 0 | 0 |
| [T1602.001](/mitre/techniques/T1602-001.md) SNMP (MIB Dump) | collection | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1041](/mitre/mitigations/M1041.md) [M1051](/mitre/mitigations/M1051.md) [M1054](/mitre/mitigations/M1054.md) | 25 | 0 | 0 |
| [T1602.002](/mitre/techniques/T1602-002.md) Network Device Configuration Dump | collection | [M1030](/mitre/mitigations/M1030.md) [M1031](/mitre/mitigations/M1031.md) [M1037](/mitre/mitigations/M1037.md) [M1041](/mitre/mitigations/M1041.md) [M1051](/mitre/mitigations/M1051.md) [M1054](/mitre/mitigations/M1054.md) | 25 | 0 | 0 |
| [T1606](/mitre/techniques/T1606.md) Forge Web Credentials | credential-access | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) | 7 | 9 | 0 |
| [T1606.001](/mitre/techniques/T1606-001.md) Web Cookies | credential-access | [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) | 4 | 9 | 0 |
| [T1606.002](/mitre/techniques/T1606-002.md) SAML Tokens | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1047](/mitre/mitigations/M1047.md) | 4 | 0 | 0 |
| [T1608](/mitre/techniques/T1608.md) Stage Capabilities | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1608.001](/mitre/techniques/T1608-001.md) Upload Malware | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1608.002](/mitre/techniques/T1608-002.md) Upload Tool | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1608.003](/mitre/techniques/T1608-003.md) Install Digital Certificate | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1608.004](/mitre/techniques/T1608-004.md) Drive-by Target | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1608.005](/mitre/techniques/T1608-005.md) Link Target | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1608.006](/mitre/techniques/T1608-006.md) SEO Poisoning | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1609](/mitre/techniques/T1609.md) Container Administration Command | execution | [M1018](/mitre/mitigations/M1018.md) [M1026](/mitre/mitigations/M1026.md) [M1035](/mitre/mitigations/M1035.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) | 11 | 0 | 0 |
| [T1610](/mitre/techniques/T1610.md) Deploy Container | defense-evasion, execution | [M1018](/mitre/mitigations/M1018.md) [M1030](/mitre/mitigations/M1030.md) [M1035](/mitre/mitigations/M1035.md) [M1047](/mitre/mitigations/M1047.md) | 9 | 0 | 0 |
| [T1611](/mitre/techniques/T1611.md) Escape to Host ⭐ | privilege-escalation | [M1026](/mitre/mitigations/M1026.md) [M1038](/mitre/mitigations/M1038.md) [M1042](/mitre/mitigations/M1042.md) [M1048](/mitre/mitigations/M1048.md) [M1051](/mitre/mitigations/M1051.md) | 19 | 0 | 0 |
| [T1612](/mitre/techniques/T1612.md) Build Image on Host | defense-evasion | [M1026](/mitre/mitigations/M1026.md) [M1030](/mitre/mitigations/M1030.md) [M1035](/mitre/mitigations/M1035.md) [M1047](/mitre/mitigations/M1047.md) | 11 | 0 | 0 |
| [T1613](/mitre/techniques/T1613.md) Container and Resource Discovery | discovery | [M1018](/mitre/mitigations/M1018.md) [M1030](/mitre/mitigations/M1030.md) [M1035](/mitre/mitigations/M1035.md) | 10 | 0 | 0 |
| [T1614](/mitre/techniques/T1614.md) System Location Discovery | discovery | - | 0 | 2 | 0 |
| [T1614.001](/mitre/techniques/T1614-001.md) System Language Discovery | discovery | - | 0 | 3 | 0 |
| [T1615](/mitre/techniques/T1615.md) Group Policy Discovery | discovery | - | 0 | 4 | 0 |
| [T1619](/mitre/techniques/T1619.md) Cloud Storage Object Discovery | discovery | [M1018](/mitre/mitigations/M1018.md) | 7 | 6 | 0 |
| [T1620](/mitre/techniques/T1620.md) Reflective Code Loading | defense-evasion | - | 0 | 2 | 0 |
| [T1621](/mitre/techniques/T1621.md) Multi-Factor Authentication Request Generation | credential-access | [M1017](/mitre/mitigations/M1017.md) [M1032](/mitre/mitigations/M1032.md) [M1036](/mitre/mitigations/M1036.md) | 7 | 12 | 0 |
| [T1622](/mitre/techniques/T1622.md) Debugger Evasion | defense-evasion, discovery | - | 15 | 0 | 0 |
| [T1647](/mitre/techniques/T1647.md) Plist File Modification | defense-evasion | [M1013](/mitre/mitigations/M1013.md) | 15 | 0 | 0 |
| [T1648](/mitre/techniques/T1648.md) Serverless Execution | execution | [M1018](/mitre/mitigations/M1018.md) [M1036](/mitre/mitigations/M1036.md) | 8 | 0 | 0 |
| [T1649](/mitre/techniques/T1649.md) Steal or Forge Authentication Certificates | credential-access | [M1015](/mitre/mitigations/M1015.md) [M1041](/mitre/mitigations/M1041.md) [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) | 3 | 20 | 0 |
| [T1650](/mitre/techniques/T1650.md) Acquire Access | resource-development | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |
| [T1651](/mitre/techniques/T1651.md) Cloud Administration Command | execution | [M1026](/mitre/mitigations/M1026.md) | 6 | 0 | 0 |
| [T1652](/mitre/techniques/T1652.md) Device Driver Discovery | discovery | - | 0 | 0 | 0 |
| [T1653](/mitre/techniques/T1653.md) Power Settings | persistence | [M1047](/mitre/mitigations/M1047.md) | 4 | 0 | 0 |
| [T1654](/mitre/techniques/T1654.md) Log Enumeration | discovery | [M1018](/mitre/mitigations/M1018.md) | 4 | 0 | 0 |
| [T1656](/mitre/techniques/T1656.md) Impersonation | defense-evasion | [M1017](/mitre/mitigations/M1017.md) [M1019](/mitre/mitigations/M1019.md) | 0 | 0 | 0 |
| [T1657](/mitre/techniques/T1657.md) Financial Theft | impact | [M1017](/mitre/mitigations/M1017.md) [M1018](/mitre/mitigations/M1018.md) | 2 | 0 | 0 |
| [T1659](/mitre/techniques/T1659.md) Content Injection | initial-access, command-and-control | [M1021](/mitre/mitigations/M1021.md) [M1041](/mitre/mitigations/M1041.md) | 3 | 0 | 0 |
| [T1665](/mitre/techniques/T1665.md) Hide Infrastructure | command-and-control | - | 0 | 0 | 0 |
| [T1666](/mitre/techniques/T1666.md) Modify Cloud Resource Hierarchy | defense-evasion | [M1018](/mitre/mitigations/M1018.md) [M1047](/mitre/mitigations/M1047.md) [M1054](/mitre/mitigations/M1054.md) | 1 | 2 | 0 |
| [T1667](/mitre/techniques/T1667.md) Email Bombing | impact | [M1017](/mitre/mitigations/M1017.md) [M1054](/mitre/mitigations/M1054.md) | 0 | 0 | 0 |
| [T1668](/mitre/techniques/T1668.md) Exclusive Control | persistence | - | 0 | 0 | 0 |
| [T1669](/mitre/techniques/T1669.md) Wi-Fi Networks | initial-access | [M1030](/mitre/mitigations/M1030.md) [M1032](/mitre/mitigations/M1032.md) [M1041](/mitre/mitigations/M1041.md) | 0 | 0 | 0 |
| [T1671](/mitre/techniques/T1671.md) Cloud Application Integration | persistence | [M1042](/mitre/mitigations/M1042.md) [M1047](/mitre/mitigations/M1047.md) | 0 | 0 | 0 |
| [T1672](/mitre/techniques/T1672.md) Email Spoofing | defense-evasion | [M1054](/mitre/mitigations/M1054.md) | 0 | 0 | 0 |
| [T1673](/mitre/techniques/T1673.md) Virtual Machine Discovery | discovery | - | 0 | 0 | 0 |
| [T1674](/mitre/techniques/T1674.md) Input Injection | execution | [M1034](/mitre/mitigations/M1034.md) [M1038](/mitre/mitigations/M1038.md) | 0 | 0 | 0 |
| [T1675](/mitre/techniques/T1675.md) ESXi Administration Command | execution | [M1018](/mitre/mitigations/M1018.md) | 0 | 0 | 0 |
| [T1677](/mitre/techniques/T1677.md) Poisoned Pipeline Execution | execution | [M1018](/mitre/mitigations/M1018.md) [M1054](/mitre/mitigations/M1054.md) | 0 | 0 | 0 |
| [T1678](/mitre/techniques/T1678.md) Delay Execution | defense-evasion | - | 0 | 0 | 0 |
| [T1679](/mitre/techniques/T1679.md) Selective Exclusion | defense-evasion | - | 0 | 0 | 0 |
| [T1680](/mitre/techniques/T1680.md) Local Storage Discovery | discovery | - | 0 | 0 | 0 |
| [T1681](/mitre/techniques/T1681.md) Search Threat Vendor Data | reconnaissance | [M1056](/mitre/mitigations/M1056.md) | 0 | 0 | 0 |

---

*Source: MITRE ATT&CK® v19.2, D3FEND™, CAPEC™, NIST SP 800-53 Rev5 — trademarks of their owners. Independent reference summary; mitigation↔control↔D3FEND associations are mechanically derived from the per-technique mappings, not an official MITRE crosswalk.*

