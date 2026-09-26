# MITRE D3FEND Countermeasure Reference

> [MITRE D3FEND](https://d3fend.mitre.org/) is the defensive counterpart to ATT&CK — a knowledge base of **cybersecurity countermeasures**. This reference maps **156 D3FEND defensive techniques** to the **426 ATT&CK techniques** they counter (via the digital artifacts each acts on), completing the *defense* node of the [threat-informed knowledge graph](THREAT_INFORMED_DEFENSE_REFERENCE.md): **CVE → CWE → CAPEC → ATT&CK → D3FEND**.

| | |
|---|---|
| **Read this when** | you know which ATT&CK technique threatens you and need the countermeasures that blunt it, you are planning defensive coverage across Model/Harden/Detect/Isolate/Deceive/Evict/Restore, you want the machine-readable ATT&CK-to-D3FEND mapping for tooling |
| **Start at** | [The 7 defensive tactics](#the-7-defensive-tactics) for the lay of the land, [Detect](#detect) for the largest tactic (56 techniques), [ATT&CK technique to D3FEND countermeasures](#attampck-technique-d3fend-countermeasures-most-covered) to work backward from a threat |
| **Pairs with** | [THREAT_INFORMED_DEFENSE_REFERENCE.md](THREAT_INFORMED_DEFENSE_REFERENCE.md), [CVE_REFERENCE.md](CVE_REFERENCE.md), [ENGAGE_REFERENCE.md](ENGAGE_REFERENCE.md), [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md) |

Machine-readable: [`data/attack/technique_to_d3fend.jsonl`](data/attack/technique_to_d3fend.jsonl). Source: D3FEND ontology full inferred mappings.

## The 7 defensive tactics

| Tactic | Purpose | Defensive techniques |
|---|---|--:|
| **Model** | Inventory and understand the system — assets, data flows, and dependencies. | 12 |
| **Harden** | Reduce attack surface before an attack (credential, message, platform, application hardening). | 32 |
| **Detect** | Identify adversary activity through analysis of artifacts and behaviors. | 56 |
| **Isolate** | Create barriers between system components to limit adversary movement. | 29 |
| **Deceive** | Advertise, entice, and expose the adversary with decoys and lures. | 4 |
| **Evict** | Remove an adversary from the environment. | 14 |
| **Restore** | Return the system to a known-good state after an incident. | 9 |

---

## Model

*Inventory and understand the system — assets, data flows, and dependencies.*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Access Modeling | 27 — DE-0006, T0812, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004 +19 |
| Asset Vulnerability Enumeration | 45 — DE-0007, DE-0008, EX-0003, EX-0004, EX-0009.01, EX-0010.03, EX-0010.04, EX-0012.03 +37 |
| Configuration Inventory | 62 — DE-0006, EX-0012.02, EX-0012.04, EX-0012.05, EX-0012.10, EXF-0006.01, IA-0002, T0858 +54 |
| Container Image Analysis | 1 — T1525 |
| Data Inventory | 31 — T0865, T0894, T1003.002, T1003.004, T1003.008, T1012, T1033, T1112 +23 |
| Hardware Component Inventory | 21 — EX-0004, EX-0007, EX-0016.01, EX-0016.02, EXF-0006.01, EXF-0006.02, IA-0002, PER-0001 +13 |
| Logical Link Mapping | 17 — EX-0015, EX-0018, T0807, T0809, T0816, T0848, T0857, T0864 +9 |
| Network Node Inventory | 17 — EX-0015, EX-0018, T0807, T0809, T0816, T0848, T0857, T0864 +9 |
| Network Traffic Policy Mapping | 9 — DE-0006, T1134.005, T1222, T1484, T1548.001, T1548.005, T1552.006, T1556.009 +1 |
| Physical Link Mapping | 22 — DE-0002, EX-0015, EX-0016.01, EX-0016.02, EX-0018, T0807, T0809, T0816 +14 |
| Software Inventory | 45 — DE-0007, DE-0008, EX-0003, EX-0004, EX-0009.01, EX-0010.03, EX-0010.04, EX-0012.03 +37 |
| System Vulnerability Assessment | 1 — T1562.010 |

## Harden

*Reduce attack surface before an attack (credential, message, platform, application hardening).*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Agent Authentication | 19 — T0812, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004, T1087.001 +11 |
| Application Configuration Hardening | 10 — EX-0012.02, EX-0012.04, EX-0012.05, EX-0012.10, T0858, T0868, T1114.003, T1562.002 +2 |
| Bootloader Authentication | 4 — DE-0008, EX-0004, EX-0010.04, T1542.003 |
| Certificate Pinning | 1 — T1649 |
| Certificate Rotation | 1 — T1649 |
| Certificate-based Authentication | 1 — T1649 |
| Change Default Password | 23 — T0812, T0848, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004 +15 |
| Credential Hardening | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| Credential Rotation | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| Credential Scrubbing | 2 — EX-0012.03, T1505.001 |
| Disable Remote Access | 10 — EX-0012.02, EX-0012.04, EX-0012.05, EX-0012.10, T0858, T0868, T1114.003, T1562.002 +2 |
| Disk Encryption | 5 — EX-0004, EX-0007, PER-0001, T1564.005, T1619 |
| Domain Logic Validation | 2 — EX-0012.03, T1505.001 |
| File Encryption | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Hardware-based Write Protection | 2 — EX-0007, T1619 |
| Message Authentication | 35 — EX-0001.01, EX-0005.02, EX-0013.01, T0800, T0801, T0802, T0803, T0805 +27 |
| Message Encryption | 35 — EX-0001.01, EX-0005.02, EX-0013.01, T0800, T0801, T0802, T0803, T0805 +27 |
| Multi-factor Authentication | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| One-time Password | 4 — T0812, T1110.001, T1110.002, T1110.003 |
| Password Authentication | 4 — T0812, T1110.001, T1110.002, T1110.003 |
| Password Rotation | 4 — T0812, T1110.001, T1110.002, T1110.003 |
| Process Segment Execution Prevention | 17 — T0820, T0866, T0874, T0890, T0894, T1033, T1055.012, T1056.004 +9 |
| Radiation Hardening | 21 — EX-0004, EX-0007, EX-0016.01, EX-0016.02, EXF-0006.01, EXF-0006.02, IA-0002, PER-0001 +13 |
| Segment Address Offset Randomization | 17 — T0820, T0866, T0874, T0890, T0894, T1033, T1055.012, T1056.004 +9 |
| Software Update | 45 — DE-0007, DE-0008, EX-0003, EX-0004, EX-0009.01, EX-0010.03, EX-0010.04, EX-0012.03 +37 |
| Stack Frame Canary Validation | 8 — T0820, T0866, T0890, T1068, T1203, T1210, T1211, T1212 |
| Strong Password Policy | 4 — T0812, T1110.001, T1110.002, T1110.003 |
| System Configuration Permissions | 14 — T0894, T1012, T1112, T1137.006, T1207, T1218.014, T1543.003, T1546.012 +6 |
| Token Binding | 7 — T1134.001, T1134.002, T1134.003, T1528, T1550.001, T1558, T1558.001 |
| Token-based Authentication | 7 — T1134.001, T1134.002, T1134.003, T1528, T1550.001, T1558, T1558.001 |
| Trusted Library | 2 — EX-0012.03, T1505.001 |
| Variable Initialization | 2 — EX-0012.03, T1505.001 |

## Detect

*Identify adversary activity through analysis of artifacts and behaviors.*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Administrative Network Activity Analysis | 8 — T1003.006, T1047, T1098.001, T1110.003, T1110.004, T1207, T1546.003, T1546.008 |
| Application Exception Monitoring | 16 — DE-0003.08, DE-0010, T1003.005, T1003.006, T1070.001, T1070.003, T1110.001, T1110.003 +8 |
| Application Protocol Command Analysis | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| Certificate Analysis | 6 — T1041, T1048.002, T1071, T1071.001, T1573.002, T1649 |
| Client-server Payload Profiling | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| Connection Attempt Analysis | 18 — T0866, T0884, T0886, T1003.006, T1021, T1047, T1090.001, T1098.001 +10 |
| Credential Compromise Scope Analysis | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| DNS Traffic Analysis | 4 — T0842, T1040, T1071.004, T1568 |
| Database Query String Analysis | 1 — T1190 |
| Domain Account Monitoring | 5 — T1078.002, T1087.002, T1098.002, T1098.003, T1136.002 |
| Dynamic Analysis | 43 — T0853, T0865, T0871, T0894, T0895, T1016, T1027.001, T1027.002 +35 |
| Emulated File Analysis | 43 — T0853, T0865, T0871, T0894, T0895, T1016, T1027.001, T1027.002 +35 |
| Endpoint Health Beacon | 17 — EX-0015, EX-0018, T0807, T0809, T0816, T0848, T0857, T0864 +9 |
| File Analysis | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| File Carving | 2 — T1071.002, T1570 |
| File Creation Analysis | 2 — T1074.001, T1218.001 |
| File Integrity Monitoring | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Firmware Behavior Analysis | 8 — DE-0007, EX-0010.03, T0839, T0851, T1014, T1542.001, T1542.002, T1542.004 |
| Firmware Embedded Monitoring Code | 8 — DE-0007, EX-0010.03, T0839, T0851, T1014, T1542.001, T1542.002, T1542.004 |
| Firmware Verification | 8 — DE-0007, EX-0010.03, T0839, T0851, T1014, T1542.001, T1542.002, T1542.004 |
| Homoglyph Detection | 9 — T0817, T0865, T1114.001, T1189, T1204.001, T1534, T1566.001, T1566.002 +1 |
| IPC Traffic Analysis | 1 — T1197 |
| Identifier Activity Analysis | 5 — T0817, T1189, T1204.001, T1566.002, T1566.003 |
| Inbound Session Volume Analysis | 9 — T0819, T0822, T0865, T1190, T1498.001, T1498.002, T1499.002, T1566.001 +1 |
| Input Device Analysis | 3 — T1056.001, T1123, T1125 |
| Local Account Monitoring | 3 — T1078.003, T1087.001, T1136.001 |
| Memory Boundary Tracking | 11 — T0820, T0866, T0874, T0890, T1055.012, T1056.004, T1068, T1203 +3 |
| Network Traffic Community Deviation | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| Network Traffic Signature Analysis | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| Operating Mode Monitoring | 2 — T0800, T0858 |
| Operational Process Monitoring | 16 — DE-0003.08, DE-0010, T0811, T1003.006, T1070.001, T1070.003, T1110.001, T1110.003 +8 |
| Per Host Download-Upload Ratio Analysis | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| Process Code Segment Verification | 11 — T0820, T0866, T0874, T0890, T1055.012, T1056.004, T1068, T1203 +3 |
| Process Lineage Analysis | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Process Self-Modification Detection | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Process Spawn Analysis | 48 — T0806, T0813, T0814, T0819, T0821, T0823, T0846, T0863 +40 |
| Protocol Metadata Anomaly Detection | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| RPC Traffic Analysis | 1 — T1558.003 |
| Relay Pattern Analysis | 31 — T0884, T1001, T1008, T1048.001, T1048.002, T1048.003, T1071, T1071.001 +23 |
| Remote Firmware Update Monitoring | 3 — T0800, T0814, T0839 |
| Remote Terminal Session Detection | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| Scheduled Job Analysis | 2 — T1036.004, T1053 |
| Sender MTA Reputation Analysis | 5 — T0865, T1114.001, T1534, T1566.001, T1566.002 |
| Sender Reputation Analysis | 5 — T0865, T1114.001, T1534, T1566.001, T1566.002 |
| Service Binary Verification | 13 — EX-0003, T0843, T0845, T0873, T0889, T1056.003, T1072, T1212 +5 |
| Shadow Stack Comparisons | 8 — T0820, T0866, T0890, T1068, T1203, T1210, T1211, T1212 |
| System Call Analysis | 47 — T0834, T0846, T0852, T0863, T0888, T0894, T0895, T1007 +39 |
| System Daemon Monitoring | 3 — T1053, T1053.005, T1562.001 |
| System File Analysis | 10 — T0888, T1003.007, T1018, T1036.003, T1055.009, T1070.002, T1543.002, T1548.003 +2 |
| System Firmware Verification | 4 — DE-0007, EX-0010.03, T1542.001, T1542.004 |
| System Init Config Analysis | 5 — T1037.004, T1037.005, T1547.001, T1562.009, T1574.011 |
| URL Analysis | 5 — T0817, T1189, T1204.001, T1566.002, T1566.003 |
| URL Reputation Analysis | 5 — T0817, T1189, T1204.001, T1566.002, T1566.003 |
| User Geolocation Logon Pattern Analysis | 90 — T0814, T0817, T0819, T0822, T0830, T0840, T0842, T0846 +82 |
| User Session Init Config Analysis | 2 — T1546.004, T1564.002 |
| Video Surveillance | 1 — T1125 |

## Isolate

*Create barriers between system components to limit adversary movement.*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Application-based Process Isolation | 23 — EX-0012.03, T0806, T0813, T0814, T0819, T0821, T0823, T0878 +15 |
| Content Filtering | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Content Modification | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Content Quarantine | 123 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +115 |
| Credential Transmission Scoping | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| DNS Allowlisting | 2 — T1071.004, T1568 |
| DNS Denylisting | 2 — T1071.004, T1568 |
| Directional Network Link | 5 — DE-0002, EX-0016.01, EX-0016.02, T0860, T0887 |
| Domain Trust Policy | 1 — T1033 |
| Email Filtering | 5 — T0865, T1114.001, T1534, T1566.001, T1566.002 |
| Executable Allowlisting | 58 — T0846, T0853, T0863, T0871, T0888, T0894, T0895, T1007 +50 |
| Executable Denylisting | 58 — T0846, T0853, T0863, T0871, T0888, T0894, T0895, T1007 +50 |
| File Format Verification | 1 — T1564.009 |
| Forward Resolution Domain Denylisting | 2 — T1071.004, T1568 |
| Hardware-based Process Isolation | 48 — T0806, T0813, T0814, T0819, T0821, T0823, T0846, T0863 +40 |
| IO Port Restriction | 9 — T0847, T0860, T1025, T1052.001, T1056.001, T1091, T1092, T1123 +1 |
| Inbound Traffic Filtering | 9 — T0819, T0822, T0865, T1190, T1498.001, T1498.002, T1499.002, T1566.001 +1 |
| Kernel-based Process Isolation | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Local File Permissions | 111 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +103 |
| Network Resource Access Mediation | 8 — T1037.003, T1039, T1070.005, T1074.002, T1080, T1213.001, T1213.002, T1491.002 |
| Network Traffic Filtering | 119 — EX-0001.01, EX-0005.02, EX-0013.01, T0800, T0801, T0802, T0803, T0805 +111 |
| OT Variable Access Restriction | 10 — EX-0012.07, EX-0012.08, EX-0012.09, T0801, T0806, T0809, T0835, T0836 +2 |
| Operating Mode Restriction | 2 — T0800, T0858 |
| Outbound Traffic Filtering | 32 — T0869, T0884, T1001, T1008, T1048.001, T1048.002, T1048.003, T1071 +24 |
| Remote File Access Mediation | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Reverse Resolution IP Denylisting | 2 — T1071.004, T1568 |
| System Call Filtering | 66 — T0806, T0813, T0814, T0819, T0821, T0823, T0834, T0846 +58 |
| User Account Permissions | 19 — T0812, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004, T1087.001 +11 |
| Web Session Access Mediation | 14 — T0806, T0813, T0814, T0819, T0821, T0878, T1003.001, T1003.002 +6 |

## Deceive

*Advertise, entice, and expose the adversary with decoys and lures.*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Decoy Environment | 1 — T1082 |
| Decoy File | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Decoy Network Resource | 8 — T1037.003, T1039, T1070.005, T1074.002, T1080, T1213.001, T1213.002, T1491.002 |
| Decoy User Credential | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |

## Evict

*Remove an adversary from the environment.*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Account Locking | 19 — T0812, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004, T1087.001 +11 |
| Authentication Cache Invalidation | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| Credential Revocation | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| Disk Erasure | 2 — EX-0007, T1619 |
| Disk Formatting | 2 — EX-0007, T1619 |
| Disk Partitioning | 2 — T1561.001, T1561.002 |
| Email Removal | 7 — T0865, T1114.001, T1114.002, T1505.002, T1534, T1566.001, T1566.002 |
| File Eviction | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Host Reboot | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Host Shutdown | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Process Suspension | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Process Termination | 21 — T0806, T0813, T0814, T0819, T0821, T0823, T0878, T1003.001 +13 |
| Registry Key Deletion | 1 — T1562.003 |
| Session Termination | 10 — T0807, T0822, T1021.001, T1021.004, T1133, T1134.003, T1199, T1563 +2 |

## Restore

*Return the system to a known-good state after an incident.*

| D3FEND technique | ATT&CK techniques countered |
|---|--:|
| Reissue Credential | 25 — DE-0011, PER-0005, T0812, T0891, T0892, T1003.003, T1003.005, T1003.008 +17 |
| Restore Configuration | 62 — DE-0006, EX-0012.02, EX-0012.04, EX-0012.05, EX-0012.10, EXF-0006.01, IA-0002, T0858 +54 |
| Restore Database | 23 — T0894, T1003.002, T1003.004, T1003.008, T1012, T1033, T1112, T1137.006 +15 |
| Restore Email | 5 — T0865, T1114.001, T1534, T1566.001, T1566.002 |
| Restore File | 110 — DE-0007, EX-0010.02, EX-0010.03, T0851, T0853, T0865, T0871, T0888 +102 |
| Restore Network Access | 16 — EX-0015, EX-0018, T0807, T0809, T0816, T0848, T0857, T0864 +8 |
| Restore Software | 45 — DE-0007, DE-0008, EX-0003, EX-0004, EX-0009.01, EX-0010.03, EX-0010.04, EX-0012.03 +37 |
| Restore User Account Access | 19 — T0812, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004, T1087.001 +11 |
| Unlock Account | 19 — T0812, T0859, T1078, T1078.001, T1078.002, T1078.003, T1078.004, T1087.001 +11 |

---

## ATT&CK technique → D3FEND countermeasures (most-covered)

For each ATT&CK technique, the D3FEND defensive techniques that counter it. Full mapping in the dataset.

| ATT&CK | Technique | D3FEND countermeasures |
|---|---|---|
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Spearphishing Link | Application Protocol Command Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine, Data Inventory +28 |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | Application-based Process Isolation, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +25 |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Application-based Process Isolation, Content Filtering, Content Modification, Content Quarantine, Data Inventory, Decoy File +25 |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Application Protocol Command Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine, Data Inventory +25 |
| [T1546.008](https://attack.mitre.org/techniques/T1546/008/) | Accessibility Features | Administrative Network Activity Analysis, Application Protocol Command Analysis, Client-server Payload Profiling, Configuration Inventory, Connection Attempt Analysis, Content Filtering +22 |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Administrative Network Activity Analysis, Application Exception Monitoring, Application Protocol Command Analysis, Authentication Cache Invalidation, Change Default Password, Client-server Payload Profiling +21 |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | Application Protocol Command Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine, Decoy File +21 |
| [T1212](https://attack.mitre.org/techniques/T1212/) | Exploitation for Credential Access | Application-based Process Isolation, Asset Vulnerability Enumeration, Hardware-based Process Isolation, Host Reboot, Host Shutdown, Kernel-based Process Isolation +17 |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Asymmetric Cryptography | Application Protocol Command Analysis, Certificate Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine +17 |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | Application Protocol Command Analysis, Certificate Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine +17 |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Application Protocol Command Analysis, Certificate Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine +17 |
| [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Application Protocol Command Analysis, Certificate Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine +17 |
| [T1003.008](https://attack.mitre.org/techniques/T1003/008/) | /etc/passwd and /etc/shadow | Authentication Cache Invalidation, Content Filtering, Content Modification, Content Quarantine, Credential Compromise Scope Analysis, Credential Hardening +16 |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +15 |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Application Exception Monitoring, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +15 |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Application Protocol Command Analysis, Certificate Analysis, Client-server Payload Profiling, Content Filtering, Content Modification, Content Quarantine +15 |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Additional Cloud Credentials | Administrative Network Activity Analysis, Application Protocol Command Analysis, Authentication Cache Invalidation, Client-server Payload Profiling, Connection Attempt Analysis, Credential Compromise Scope Analysis +14 |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | Application Access Token | Application Protocol Command Analysis, Authentication Cache Invalidation, Client-server Payload Profiling, Credential Compromise Scope Analysis, Credential Hardening, Credential Revocation +14 |
| [T1562.003](https://attack.mitre.org/techniques/T1562/003/) | Impair Command History Logging | Application Configuration Hardening, Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File +14 |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | Mshta | Content Filtering, Content Modification, Content Quarantine, Data Inventory, Decoy File, Dynamic Analysis +14 |
| [T1649](https://attack.mitre.org/techniques/T1649/) | Steal or Forge Authentication Certificates | Asset Vulnerability Enumeration, Certificate Analysis, Certificate Pinning, Certificate Rotation, Certificate-based Authentication, Content Filtering +14 |
| [T1534](https://attack.mitre.org/techniques/T1534/) | Internal Spearphishing | Content Filtering, Content Modification, Content Quarantine, Data Inventory, Decoy File, Dynamic Analysis +14 |
| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | Content Filtering, Content Modification, Content Quarantine, Data Inventory, Decoy File, Dynamic Analysis +14 |
| [T1546.009](https://attack.mitre.org/techniques/T1546/009/) | AppCert DLLs | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Executable Allowlisting +13 |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +13 |
| [T1220](https://attack.mitre.org/techniques/T1220/) | XSL Script Processing | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +13 |
| [T1546.010](https://attack.mitre.org/techniques/T1546/010/) | AppInit DLLs | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Executable Allowlisting +13 |
| [T1550.004](https://attack.mitre.org/techniques/T1550/004/) | Web Session Cookie | Application Protocol Command Analysis, Authentication Cache Invalidation, Client-server Payload Profiling, Credential Compromise Scope Analysis, Credential Hardening, Credential Revocation +12 |
| [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | Component Object Model Hijacking | Content Filtering, Content Modification, Content Quarantine, Data Inventory, Decoy File, Dynamic Analysis +12 |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +12 |
| [T1037.004](https://attack.mitre.org/techniques/T1037/004/) | RC Scripts | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +12 |
| [T1505.002](https://attack.mitre.org/techniques/T1505/002/) | Transport Agent | Application-based Process Isolation, Email Removal, Endpoint Health Beacon, Hardware-based Process Isolation, Host Reboot, Host Shutdown +12 |
| [T1014](https://attack.mitre.org/techniques/T1014/) | Rootkit | Asset Vulnerability Enumeration, Content Filtering, Content Modification, Content Quarantine, Decoy File, File Analysis +12 |
| [T1546.005](https://attack.mitre.org/techniques/T1546/005/) | Trap | Application Exception Monitoring, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +11 |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | Thread Execution Hijacking | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +11 |
| [T1037.003](https://attack.mitre.org/techniques/T1037/003/) | Network Logon Script | Content Filtering, Content Modification, Content Quarantine, Decoy File, Decoy Network Resource, Dynamic Analysis +11 |
| [T1546.002](https://attack.mitre.org/techniques/T1546/002/) | Screensaver | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +11 |
| [T1137.001](https://attack.mitre.org/techniques/T1137/001/) | Office Template Macros | Configuration Inventory, Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis +11 |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Rundll32 | Content Filtering, Content Modification, Content Quarantine, Decoy File, Executable Allowlisting, Executable Denylisting +11 |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Administrative Network Activity Analysis, Application Protocol Command Analysis, Client-server Payload Profiling, Connection Attempt Analysis, Executable Allowlisting, Executable Denylisting +11 |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Application Exception Monitoring, Authentication Cache Invalidation, Change Default Password, Credential Compromise Scope Analysis, Credential Hardening, Credential Revocation +10 |
| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Rename Legitimate Utilities | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +10 |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Application-based Process Isolation, Executable Allowlisting, Executable Denylisting, Hardware-based Process Isolation, Host Reboot, Host Shutdown +10 |
| [T1072](https://attack.mitre.org/techniques/T1072/) | Software Deployment Tools | Asset Vulnerability Enumeration, Content Filtering, Content Modification, Content Quarantine, Decoy File, File Analysis +10 |
| [T1564.006](https://attack.mitre.org/techniques/T1564/006/) | Run Virtual Instance | Asset Vulnerability Enumeration, Content Filtering, Content Modification, Content Quarantine, Decoy File, File Analysis +10 |
| [T1210](https://attack.mitre.org/techniques/T1210/) | Exploitation of Remote Services | Application Protocol Command Analysis, Client-server Payload Profiling, Connection Attempt Analysis, Memory Boundary Tracking, Network Traffic Community Deviation, Network Traffic Filtering +10 |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | Application Protocol Command Analysis, Client-server Payload Profiling, DNS Allowlisting, DNS Denylisting, DNS Traffic Analysis, Forward Resolution Domain Denylisting +10 |
| [T1568](https://attack.mitre.org/techniques/T1568/) | Dynamic Resolution | Application Protocol Command Analysis, Client-server Payload Profiling, DNS Allowlisting, DNS Denylisting, DNS Traffic Analysis, Forward Resolution Domain Denylisting +10 |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1546.006](https://attack.mitre.org/techniques/T1546/006/) | LC_LOAD_DYLIB Addition | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1036.001](https://attack.mitre.org/techniques/T1036/001/) | Invalid Code Signature | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | Binary Padding | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | Shortcut Modification | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1037.002](https://attack.mitre.org/techniques/T1037/002/) | Login Hook | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1037.001](https://attack.mitre.org/techniques/T1037/001/) | Logon Script (Windows) | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1546.013](https://attack.mitre.org/techniques/T1546/013/) | PowerShell Profile | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1027.004](https://attack.mitre.org/techniques/T1027/004/) | Compile After Delivery | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | Software Packing | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |
| [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | Path Interception by Unquoted Path | Content Filtering, Content Modification, Content Quarantine, Decoy File, Dynamic Analysis, Emulated File Analysis +9 |

---

*Source: MITRE D3FEND ontology (full inferred ATT&CK↔D3FEND mappings). D3FEND is a complement to, not a replacement for, environment-specific defensive design.*
