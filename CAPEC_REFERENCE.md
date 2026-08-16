# CAPEC Attack Pattern Reference

> [MITRE CAPEC](https://capec.mitre.org/) (Common Attack Pattern Enumeration and Classification) describes the **615 common patterns of attack** that exploit software weaknesses. CAPEC is the *attack-pattern* bridge between **CWE** (the weakness) and **ATT&CK** (the adversary behavior) in the [knowledge graph](THREAT_INFORMED_DEFENSE_REFERENCE.md). **177** patterns carry an explicit ATT&CK technique mapping.

Machine-readable: [`data/weaknesses/capec.jsonl`](data/weaknesses/capec.jsonl). Related: [CWE Weaknesses](CWE_REFERENCE.md) · [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md).

**Abstraction:** 77 Meta · 197 Standard · 341 Detailed.

## Attack patterns mapped to ATT&CK

Patterns with an explicit ATT&CK technique mapping — the direct CAPEC → ATT&CK bridge.

| CAPEC | Pattern | Severity | ATT&CK techniques | Related CWE |
|---|---|---|---|---|
| [CAPEC-1](https://capec.mitre.org/data/definitions/1.html) | Accessing Functionality Not Properly Constrained by ACLs | High | [T1574.010](https://attack.mitre.org/techniques/T1574/010/) | CWE-276, CWE-285, CWE-434, CWE-693 |
| [CAPEC-2](https://capec.mitre.org/data/definitions/2.html) | Inducing Account Lockout | Medium | [T1531](https://attack.mitre.org/techniques/T1531/) | CWE-645 |
| [CAPEC-11](https://capec.mitre.org/data/definitions/11.html) | Cause Web Server Misclassification | High | [T1036.006](https://attack.mitre.org/techniques/T1036/006/) | CWE-430 |
| [CAPEC-13](https://capec.mitre.org/data/definitions/13.html) | Subverting Environment Variable Values | Very High | [T1562.003](https://attack.mitre.org/techniques/T1562/003/), [T1574.006](https://attack.mitre.org/techniques/T1574/006/), [T1574.007](https://attack.mitre.org/techniques/T1574/007/) | CWE-353, CWE-285, CWE-302, CWE-74 |
| [CAPEC-17](https://capec.mitre.org/data/definitions/17.html) | Using Malicious Files | Very High | [T1574.005](https://attack.mitre.org/techniques/T1574/005/), [T1574.010](https://attack.mitre.org/techniques/T1574/010/) | CWE-732, CWE-285, CWE-272, CWE-59 |
| [CAPEC-19](https://capec.mitre.org/data/definitions/19.html) | Embedding Scripts within Scripts | High | [T1027.009](https://attack.mitre.org/techniques/T1027/009/), [T1546.004](https://attack.mitre.org/techniques/T1546/004/), [T1546.016](https://attack.mitre.org/techniques/T1546/016/) | CWE-284 |
| [CAPEC-21](https://capec.mitre.org/data/definitions/21.html) | Exploitation of Trusted Identifiers | High | [T1134](https://attack.mitre.org/techniques/T1134/), [T1528](https://attack.mitre.org/techniques/T1528/), [T1539](https://attack.mitre.org/techniques/T1539/) | CWE-290, CWE-302, CWE-346, CWE-539 |
| [CAPEC-25](https://capec.mitre.org/data/definitions/25.html) | Forced Deadlock | High | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) | CWE-412, CWE-567, CWE-662, CWE-667 |
| [CAPEC-30](https://capec.mitre.org/data/definitions/30.html) | Hijacking a Privileged Thread of Execution | Very High | [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | CWE-270 |
| [CAPEC-31](https://capec.mitre.org/data/definitions/31.html) | Accessing/Intercepting/Modifying HTTP Cookies | High | [T1539](https://attack.mitre.org/techniques/T1539/) | CWE-565, CWE-302, CWE-311, CWE-113 |
| [CAPEC-35](https://capec.mitre.org/data/definitions/35.html) | Leverage Executable Code in Non-Executable Files | Very High | [T1027.006](https://attack.mitre.org/techniques/T1027/006/), [T1027.009](https://attack.mitre.org/techniques/T1027/009/), [T1564.009](https://attack.mitre.org/techniques/T1564/009/) | CWE-94, CWE-96, CWE-95, CWE-97 |
| [CAPEC-37](https://capec.mitre.org/data/definitions/37.html) | Retrieve Embedded Sensitive Data | Very High | [T1005](https://attack.mitre.org/techniques/T1005/), [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | CWE-226, CWE-311, CWE-525, CWE-312 |
| [CAPEC-38](https://capec.mitre.org/data/definitions/38.html) | Leveraging/Manipulating Configuration File Search Paths | Very High | [T1574.007](https://attack.mitre.org/techniques/T1574/007/), [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | CWE-426, CWE-427 |
| [CAPEC-49](https://capec.mitre.org/data/definitions/49.html) | Password Brute Forcing | High | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | CWE-521, CWE-262, CWE-263, CWE-257 |
| [CAPEC-55](https://capec.mitre.org/data/definitions/55.html) | Rainbow Table Password Cracking | Medium | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | CWE-261, CWE-521, CWE-262, CWE-263 |
| [CAPEC-57](https://capec.mitre.org/data/definitions/57.html) | Utilizing REST's Trust in the System Resource to Obtain Sensitive Data | Very High | [T1040](https://attack.mitre.org/techniques/T1040/) | CWE-300, CWE-287, CWE-693 |
| [CAPEC-60](https://capec.mitre.org/data/definitions/60.html) | Reusing Session IDs (aka Session Replay) | High | [T1134.001](https://attack.mitre.org/techniques/T1134/001/), [T1550.004](https://attack.mitre.org/techniques/T1550/004/) | CWE-294, CWE-290, CWE-346, CWE-384 |
| [CAPEC-65](https://capec.mitre.org/data/definitions/65.html) | Sniff Application Code | High | [T1040](https://attack.mitre.org/techniques/T1040/) | CWE-319, CWE-311, CWE-318, CWE-693 |
| [CAPEC-68](https://capec.mitre.org/data/definitions/68.html) | Subvert Code-signing Facilities | Very High | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | CWE-325, CWE-328, CWE-1326 |
| [CAPEC-70](https://capec.mitre.org/data/definitions/70.html) | Try Common or Default Usernames and Passwords | High | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | CWE-521, CWE-262, CWE-263, CWE-798 |
| [CAPEC-94](https://capec.mitre.org/data/definitions/94.html) | Adversary in the Middle (AiTM) | Very High | [T1557](https://attack.mitre.org/techniques/T1557/) | CWE-300, CWE-290, CWE-593, CWE-287 |
| [CAPEC-98](https://capec.mitre.org/data/definitions/98.html) | Phishing | Very High | [T1566](https://attack.mitre.org/techniques/T1566/), [T1598](https://attack.mitre.org/techniques/T1598/) | CWE-451 |
| [CAPEC-112](https://capec.mitre.org/data/definitions/112.html) | Brute Force | High | [T1110](https://attack.mitre.org/techniques/T1110/) | CWE-330, CWE-326, CWE-521 |
| [CAPEC-114](https://capec.mitre.org/data/definitions/114.html) | Authentication Abuse | Medium | [T1548](https://attack.mitre.org/techniques/T1548/) | CWE-287, CWE-1244 |
| [CAPEC-115](https://capec.mitre.org/data/definitions/115.html) | Authentication Bypass | Medium | [T1548](https://attack.mitre.org/techniques/T1548/) | CWE-287 |
| [CAPEC-122](https://capec.mitre.org/data/definitions/122.html) | Privilege Abuse | Medium | [T1548](https://attack.mitre.org/techniques/T1548/) | CWE-269, CWE-732, CWE-1317 |
| [CAPEC-125](https://capec.mitre.org/data/definitions/125.html) | Flooding | Medium | [T1498.001](https://attack.mitre.org/techniques/T1498/001/), [T1499](https://attack.mitre.org/techniques/T1499/) | CWE-404, CWE-770 |
| [CAPEC-127](https://capec.mitre.org/data/definitions/127.html) | Directory Indexing | Medium | [T1083](https://attack.mitre.org/techniques/T1083/) | CWE-424, CWE-425, CWE-288, CWE-285 |
| [CAPEC-130](https://capec.mitre.org/data/definitions/130.html) | Excessive Allocation | Medium | [T1499.003](https://attack.mitre.org/techniques/T1499/003/) | CWE-404, CWE-770, CWE-1325 |
| [CAPEC-131](https://capec.mitre.org/data/definitions/131.html) | Resource Leak Exposure | Medium | [T1499](https://attack.mitre.org/techniques/T1499/) | CWE-404 |
| [CAPEC-132](https://capec.mitre.org/data/definitions/132.html) | Symlink Attack | High | [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | CWE-59 |
| [CAPEC-141](https://capec.mitre.org/data/definitions/141.html) | Cache Poisoning | High | [T1557.002](https://attack.mitre.org/techniques/T1557/002/) | CWE-348, CWE-345, CWE-349, CWE-346 |
| [CAPEC-142](https://capec.mitre.org/data/definitions/142.html) | DNS Cache Poisoning | High | [T1584.002](https://attack.mitre.org/techniques/T1584/002/) | CWE-348, CWE-345, CWE-349, CWE-346 |
| [CAPEC-148](https://capec.mitre.org/data/definitions/148.html) | Content Spoofing | Medium | [T1491](https://attack.mitre.org/techniques/T1491/) | CWE-345 |
| [CAPEC-150](https://capec.mitre.org/data/definitions/150.html) | Collect Data from Common Resource Locations | Medium | [T1003](https://attack.mitre.org/techniques/T1003/), [T1119](https://attack.mitre.org/techniques/T1119/), [T1213](https://attack.mitre.org/techniques/T1213/), [T1530](https://attack.mitre.org/techniques/T1530/), [T1555](https://attack.mitre.org/techniques/T1555/) | CWE-552, CWE-1239, CWE-1258, CWE-1266 |
| [CAPEC-158](https://capec.mitre.org/data/definitions/158.html) | Sniffing Network Traffic | Medium | [T1040](https://attack.mitre.org/techniques/T1040/), [T1111](https://attack.mitre.org/techniques/T1111/) | CWE-311 |
| [CAPEC-159](https://capec.mitre.org/data/definitions/159.html) | Redirect Access to Libraries | Very High | [T1574.008](https://attack.mitre.org/techniques/T1574/008/) | CWE-706 |
| [CAPEC-163](https://capec.mitre.org/data/definitions/163.html) | Spear Phishing | High | [T1534](https://attack.mitre.org/techniques/T1534/), [T1566.001](https://attack.mitre.org/techniques/T1566/001/), [T1566.002](https://attack.mitre.org/techniques/T1566/002/), [T1566.003](https://attack.mitre.org/techniques/T1566/003/), [T1598.001](https://attack.mitre.org/techniques/T1598/001/) | CWE-451 |
| [CAPEC-165](https://capec.mitre.org/data/definitions/165.html) | File Manipulation | Medium | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | — |
| [CAPEC-169](https://capec.mitre.org/data/definitions/169.html) | Footprinting | Very Low | [T1217](https://attack.mitre.org/techniques/T1217/), [T1592](https://attack.mitre.org/techniques/T1592/), [T1595](https://attack.mitre.org/techniques/T1595/) | CWE-200 |
| [CAPEC-177](https://capec.mitre.org/data/definitions/177.html) | Create files with the same name as files protected with a higher classification | Very High | [T1036](https://attack.mitre.org/techniques/T1036/) | CWE-706 |
| [CAPEC-180](https://capec.mitre.org/data/definitions/180.html) | Exploiting Incorrectly Configured Access Control Security Levels | Medium | [T1574.010](https://attack.mitre.org/techniques/T1574/010/) | CWE-732, CWE-1190, CWE-1191, CWE-1193 |
| [CAPEC-186](https://capec.mitre.org/data/definitions/186.html) | Malicious Software Update | High | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | CWE-494 |
| [CAPEC-187](https://capec.mitre.org/data/definitions/187.html) | Malicious Automated Software Update via Redirection | High | [T1072](https://attack.mitre.org/techniques/T1072/) | CWE-494 |
| [CAPEC-191](https://capec.mitre.org/data/definitions/191.html) | Read Sensitive Constants Within an Executable | Low | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | CWE-798 |
| [CAPEC-196](https://capec.mitre.org/data/definitions/196.html) | Session Credential Falsification through Forging | Medium | [T1134.002](https://attack.mitre.org/techniques/T1134/002/), [T1134.003](https://attack.mitre.org/techniques/T1134/003/), [T1606](https://attack.mitre.org/techniques/T1606/) | CWE-384, CWE-664 |
| [CAPEC-203](https://capec.mitre.org/data/definitions/203.html) | Manipulate Registry Information | Medium | [T1112](https://attack.mitre.org/techniques/T1112/), [T1647](https://attack.mitre.org/techniques/T1647/) | CWE-15 |
| [CAPEC-204](https://capec.mitre.org/data/definitions/204.html) | Lifting Sensitive Data Embedded in Cache | Medium | [T1005](https://attack.mitre.org/techniques/T1005/) | CWE-524, CWE-311, CWE-1239, CWE-1258 |
| [CAPEC-206](https://capec.mitre.org/data/definitions/206.html) | Signing Malicious Code | Very High | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | CWE-732 |
| [CAPEC-227](https://capec.mitre.org/data/definitions/227.html) | Sustained Client Engagement | — | [T1499](https://attack.mitre.org/techniques/T1499/) | CWE-400 |
| [CAPEC-233](https://capec.mitre.org/data/definitions/233.html) | Privilege Escalation | — | [T1548](https://attack.mitre.org/techniques/T1548/) | CWE-269, CWE-1264, CWE-1311 |
| [CAPEC-251](https://capec.mitre.org/data/definitions/251.html) | Local Code Inclusion | Medium | [T1055](https://attack.mitre.org/techniques/T1055/) | CWE-829 |
| [CAPEC-267](https://capec.mitre.org/data/definitions/267.html) | Leverage Alternate Encoding | High | [T1027](https://attack.mitre.org/techniques/T1027/) | CWE-173, CWE-172, CWE-180, CWE-181 |
| [CAPEC-268](https://capec.mitre.org/data/definitions/268.html) | Audit Log Manipulation | — | [T1070](https://attack.mitre.org/techniques/T1070/), [T1562.002](https://attack.mitre.org/techniques/T1562/002/), [T1562.003](https://attack.mitre.org/techniques/T1562/003/), [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | CWE-117 |
| [CAPEC-270](https://capec.mitre.org/data/definitions/270.html) | Modification of Registry Run Keys | Medium | [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1547.014](https://attack.mitre.org/techniques/T1547/014/) | CWE-15 |
| [CAPEC-292](https://capec.mitre.org/data/definitions/292.html) | Host Discovery | Low | [T1018](https://attack.mitre.org/techniques/T1018/) | CWE-200 |
| [CAPEC-295](https://capec.mitre.org/data/definitions/295.html) | Timestamp Request | Low | [T1124](https://attack.mitre.org/techniques/T1124/) | CWE-200 |
| [CAPEC-300](https://capec.mitre.org/data/definitions/300.html) | Port Scanning | Low | [T1046](https://attack.mitre.org/techniques/T1046/) | CWE-200 |
| [CAPEC-309](https://capec.mitre.org/data/definitions/309.html) | Network Topology Mapping | Low | [T1016](https://attack.mitre.org/techniques/T1016/), [T1049](https://attack.mitre.org/techniques/T1049/), [T1590](https://attack.mitre.org/techniques/T1590/) | CWE-200 |
| [CAPEC-312](https://capec.mitre.org/data/definitions/312.html) | Active OS Fingerprinting | Low | [T1082](https://attack.mitre.org/techniques/T1082/) | CWE-200 |
| [CAPEC-313](https://capec.mitre.org/data/definitions/313.html) | Passive OS Fingerprinting | Low | [T1082](https://attack.mitre.org/techniques/T1082/) | CWE-200 |
| [CAPEC-383](https://capec.mitre.org/data/definitions/383.html) | Harvesting Information via API Event Monitoring | Low | [T1056.004](https://attack.mitre.org/techniques/T1056/004/) | CWE-311, CWE-319, CWE-419, CWE-602 |
| [CAPEC-407](https://capec.mitre.org/data/definitions/407.html) | Pretexting | Low | [T1589](https://attack.mitre.org/techniques/T1589/) | — |
| [CAPEC-438](https://capec.mitre.org/data/definitions/438.html) | Modification During Manufacture | — | [T1195](https://attack.mitre.org/techniques/T1195/) | — |
| [CAPEC-439](https://capec.mitre.org/data/definitions/439.html) | Manipulation During Distribution | — | [T1195](https://attack.mitre.org/techniques/T1195/) | CWE-1269 |
| [CAPEC-440](https://capec.mitre.org/data/definitions/440.html) | Hardware Integrity Attack | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/), [T1200](https://attack.mitre.org/techniques/T1200/) | — |
| [CAPEC-442](https://capec.mitre.org/data/definitions/442.html) | Infected Software | High | [T1195.001](https://attack.mitre.org/techniques/T1195/001/), [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | CWE-506 |
| [CAPEC-443](https://capec.mitre.org/data/definitions/443.html) | Malicious Logic Inserted Into Product by Authorized Developer | High | [T1195.002](https://attack.mitre.org/techniques/T1195/002/), [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-445](https://capec.mitre.org/data/definitions/445.html) | Malicious Logic Insertion into Product Software via Configuration Management Manipulation | High | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | — |
| [CAPEC-446](https://capec.mitre.org/data/definitions/446.html) | Malicious Logic Insertion into Product via Inclusion of Third-Party Component | High | [T1195](https://attack.mitre.org/techniques/T1195/) | — |
| [CAPEC-448](https://capec.mitre.org/data/definitions/448.html) | Embed Virus into DLL | High | [T1027.009](https://attack.mitre.org/techniques/T1027/009/) | CWE-506 |
| [CAPEC-457](https://capec.mitre.org/data/definitions/457.html) | USB Memory Attacks | High | [T1091](https://attack.mitre.org/techniques/T1091/), [T1092](https://attack.mitre.org/techniques/T1092/) | CWE-1299 |
| [CAPEC-464](https://capec.mitre.org/data/definitions/464.html) | Evercookie | Medium | [T1606.001](https://attack.mitre.org/techniques/T1606/001/) | CWE-359 |
| [CAPEC-465](https://capec.mitre.org/data/definitions/465.html) | Transparent Proxy Abuse | Medium | [T1090.001](https://attack.mitre.org/techniques/T1090/001/) | CWE-441 |
| [CAPEC-469](https://capec.mitre.org/data/definitions/469.html) | HTTP DoS | Low | [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | CWE-770, CWE-772 |
| [CAPEC-471](https://capec.mitre.org/data/definitions/471.html) | Search Order Hijacking | Medium | [T1574.001](https://attack.mitre.org/techniques/T1574/001/), [T1574.004](https://attack.mitre.org/techniques/T1574/004/), [T1574.008](https://attack.mitre.org/techniques/T1574/008/) | CWE-427 |
| [CAPEC-473](https://capec.mitre.org/data/definitions/473.html) | Signature Spoof | — | [T1036.001](https://attack.mitre.org/techniques/T1036/001/), [T1553.002](https://attack.mitre.org/techniques/T1553/002/) | CWE-20, CWE-327, CWE-290 |
| [CAPEC-474](https://capec.mitre.org/data/definitions/474.html) | Signature Spoofing by Key Theft | High | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | CWE-522 |
| [CAPEC-478](https://capec.mitre.org/data/definitions/478.html) | Modification of Windows Service Configuration | High | [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1574.011](https://attack.mitre.org/techniques/T1574/011/) | CWE-284 |
| [CAPEC-479](https://capec.mitre.org/data/definitions/479.html) | Malicious Root Certificate | Low | [T1553.004](https://attack.mitre.org/techniques/T1553/004/) | CWE-284 |
| [CAPEC-480](https://capec.mitre.org/data/definitions/480.html) | Escaping Virtualization | Very High | [T1611](https://attack.mitre.org/techniques/T1611/) | CWE-693 |
| [CAPEC-481](https://capec.mitre.org/data/definitions/481.html) | Contradictory Destinations in Traffic Routing Schemes | High | [T1090.004](https://attack.mitre.org/techniques/T1090/004/) | CWE-923 |
| [CAPEC-482](https://capec.mitre.org/data/definitions/482.html) | TCP Flood | — | [T1498.001](https://attack.mitre.org/techniques/T1498/001/), [T1499.001](https://attack.mitre.org/techniques/T1499/001/), [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | CWE-770 |
| [CAPEC-485](https://capec.mitre.org/data/definitions/485.html) | Signature Spoofing by Key Recreation | High | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | CWE-330 |
| [CAPEC-488](https://capec.mitre.org/data/definitions/488.html) | HTTP Flood | — | [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | CWE-770 |
| [CAPEC-489](https://capec.mitre.org/data/definitions/489.html) | SSL Flood | — | [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | CWE-770 |
| [CAPEC-490](https://capec.mitre.org/data/definitions/490.html) | Amplification | — | [T1498.002](https://attack.mitre.org/techniques/T1498/002/) | CWE-770 |
| [CAPEC-497](https://capec.mitre.org/data/definitions/497.html) | File Discovery | Very Low | [T1083](https://attack.mitre.org/techniques/T1083/) | CWE-200 |
| [CAPEC-504](https://capec.mitre.org/data/definitions/504.html) | Task Impersonation | High | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) | CWE-1021 |
| [CAPEC-509](https://capec.mitre.org/data/definitions/509.html) | Kerberoasting | High | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | CWE-522, CWE-308, CWE-309, CWE-294 |
| [CAPEC-511](https://capec.mitre.org/data/definitions/511.html) | Infiltration of Software Development Environment | High | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | — |
| [CAPEC-516](https://capec.mitre.org/data/definitions/516.html) | Hardware Component Substitution During Baselining | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-520](https://capec.mitre.org/data/definitions/520.html) | Counterfeit Hardware Component Inserted During Product Assembly | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-522](https://capec.mitre.org/data/definitions/522.html) | Malicious Hardware Component Replacement | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-523](https://capec.mitre.org/data/definitions/523.html) | Malicious Software Implanted | High | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | — |
| [CAPEC-528](https://capec.mitre.org/data/definitions/528.html) | XML Flood | Medium | [T1498.001](https://attack.mitre.org/techniques/T1498/001/), [T1499.002](https://attack.mitre.org/techniques/T1499/002/) | CWE-770 |
| [CAPEC-531](https://capec.mitre.org/data/definitions/531.html) | Hardware Component Substitution | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-532](https://capec.mitre.org/data/definitions/532.html) | Altered Installed BIOS | High | [T1495](https://attack.mitre.org/techniques/T1495/), [T1542.001](https://attack.mitre.org/techniques/T1542/001/) | — |
| [CAPEC-537](https://capec.mitre.org/data/definitions/537.html) | Infiltration of Hardware Development Environment | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-538](https://capec.mitre.org/data/definitions/538.html) | Open-Source Library Manipulation | High | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | CWE-494, CWE-829 |
| [CAPEC-539](https://capec.mitre.org/data/definitions/539.html) | ASIC With Malicious Functionality | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-541](https://capec.mitre.org/data/definitions/541.html) | Application Fingerprinting | Low | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) | CWE-204, CWE-205, CWE-208 |
| [CAPEC-542](https://capec.mitre.org/data/definitions/542.html) | Targeted Malware | — | [T1027](https://attack.mitre.org/techniques/T1027/), [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | — |
| [CAPEC-543](https://capec.mitre.org/data/definitions/543.html) | Counterfeit Websites | High | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | — |
| [CAPEC-545](https://capec.mitre.org/data/definitions/545.html) | Pull Data from System Resources | — | [T1005](https://attack.mitre.org/techniques/T1005/), [T1555.001](https://attack.mitre.org/techniques/T1555/001/) | CWE-1239, CWE-1243, CWE-1258, CWE-1266 |
| [CAPEC-550](https://capec.mitre.org/data/definitions/550.html) | Install New Service | — | [T1543](https://attack.mitre.org/techniques/T1543/) | CWE-284 |
| [CAPEC-551](https://capec.mitre.org/data/definitions/551.html) | Modify Existing Service | — | [T1543](https://attack.mitre.org/techniques/T1543/) | CWE-284, CWE-522 |
| [CAPEC-552](https://capec.mitre.org/data/definitions/552.html) | Install Rootkit  | High | [T1014](https://attack.mitre.org/techniques/T1014/), [T1542.003](https://attack.mitre.org/techniques/T1542/003/), [T1547.006](https://attack.mitre.org/techniques/T1547/006/) | CWE-284 |
| [CAPEC-555](https://capec.mitre.org/data/definitions/555.html) | Remote Services with Stolen Credentials | Very High | [T1021](https://attack.mitre.org/techniques/T1021/), [T1114.002](https://attack.mitre.org/techniques/T1114/002/), [T1133](https://attack.mitre.org/techniques/T1133/) | CWE-522, CWE-308, CWE-309, CWE-294 |
| [CAPEC-556](https://capec.mitre.org/data/definitions/556.html) | Replace File Extension Handlers | — | [T1546.001](https://attack.mitre.org/techniques/T1546/001/) | CWE-284 |
| [CAPEC-558](https://capec.mitre.org/data/definitions/558.html) | Replace Trusted Executable | High | [T1505.005](https://attack.mitre.org/techniques/T1505/005/), [T1546.008](https://attack.mitre.org/techniques/T1546/008/) | CWE-284 |
| [CAPEC-560](https://capec.mitre.org/data/definitions/560.html) | Use of Known Domain Credentials | High | [T1078](https://attack.mitre.org/techniques/T1078/) | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-561](https://capec.mitre.org/data/definitions/561.html) | Windows Admin Shares with Stolen Credentials | — | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | CWE-522, CWE-308, CWE-309, CWE-294 |
| [CAPEC-562](https://capec.mitre.org/data/definitions/562.html) | Modify Shared File | — | [T1080](https://attack.mitre.org/techniques/T1080/) | CWE-284 |
| [CAPEC-564](https://capec.mitre.org/data/definitions/564.html) | Run Software at Logon | — | [T1037](https://attack.mitre.org/techniques/T1037/), [T1543.001](https://attack.mitre.org/techniques/T1543/001/), [T1543.004](https://attack.mitre.org/techniques/T1543/004/), [T1547](https://attack.mitre.org/techniques/T1547/) | CWE-284 |
| [CAPEC-565](https://capec.mitre.org/data/definitions/565.html) | Password Spraying | High | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | CWE-521, CWE-262, CWE-263, CWE-654 |
| [CAPEC-568](https://capec.mitre.org/data/definitions/568.html) | Capture Credentials via Keylogger | High | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | — |
| [CAPEC-569](https://capec.mitre.org/data/definitions/569.html) | Collect Data as Provided by Users | — | [T1056](https://attack.mitre.org/techniques/T1056/) | — |
| [CAPEC-571](https://capec.mitre.org/data/definitions/571.html) | Block Logging to Central Repository | Low | [T1562.002](https://attack.mitre.org/techniques/T1562/002/), [T1562.006](https://attack.mitre.org/techniques/T1562/006/), [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | — |
| [CAPEC-572](https://capec.mitre.org/data/definitions/572.html) | Artificially Inflate File Sizes | Medium | [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | — |
| [CAPEC-573](https://capec.mitre.org/data/definitions/573.html) | Process Footprinting | Low | [T1057](https://attack.mitre.org/techniques/T1057/) | CWE-200 |
| [CAPEC-574](https://capec.mitre.org/data/definitions/574.html) | Services Footprinting | Low | [T1007](https://attack.mitre.org/techniques/T1007/) | CWE-200 |
| [CAPEC-575](https://capec.mitre.org/data/definitions/575.html) | Account Footprinting | Low | [T1087](https://attack.mitre.org/techniques/T1087/) | CWE-200 |
| [CAPEC-576](https://capec.mitre.org/data/definitions/576.html) | Group Permission Footprinting | Low | [T1069](https://attack.mitre.org/techniques/T1069/), [T1615](https://attack.mitre.org/techniques/T1615/) | CWE-200 |
| [CAPEC-577](https://capec.mitre.org/data/definitions/577.html) | Owner Footprinting | Low | [T1033](https://attack.mitre.org/techniques/T1033/) | CWE-200 |
| [CAPEC-578](https://capec.mitre.org/data/definitions/578.html) | Disable Security Software | Medium | [T1556.006](https://attack.mitre.org/techniques/T1556/006/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1562.002](https://attack.mitre.org/techniques/T1562/002/), [T1562.004](https://attack.mitre.org/techniques/T1562/004/), [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | CWE-284 |
| [CAPEC-579](https://capec.mitre.org/data/definitions/579.html) | Replace Winlogon Helper DLL | — | [T1547.004](https://attack.mitre.org/techniques/T1547/004/) | CWE-15 |
| [CAPEC-580](https://capec.mitre.org/data/definitions/580.html) | System Footprinting | Low | [T1082](https://attack.mitre.org/techniques/T1082/) | CWE-204, CWE-205, CWE-208 |
| [CAPEC-581](https://capec.mitre.org/data/definitions/581.html) | Security Software Footprinting | — | [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | — |
| [CAPEC-593](https://capec.mitre.org/data/definitions/593.html) | Session Hijacking | Very High | [T1185](https://attack.mitre.org/techniques/T1185/), [T1550.001](https://attack.mitre.org/techniques/T1550/001/), [T1563](https://attack.mitre.org/techniques/T1563/) | CWE-287 |
| [CAPEC-600](https://capec.mitre.org/data/definitions/600.html) | Credential Stuffing | High | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-609](https://capec.mitre.org/data/definitions/609.html) | Cellular Traffic Intercept | Low | [T1111](https://attack.mitre.org/techniques/T1111/) | CWE-311 |
| [CAPEC-616](https://capec.mitre.org/data/definitions/616.html) | Establish Rogue Location | Medium | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | CWE-200 |
| [CAPEC-620](https://capec.mitre.org/data/definitions/620.html) | Drop Encryption Level | High | [T1600](https://attack.mitre.org/techniques/T1600/) | CWE-757 |
| [CAPEC-633](https://capec.mitre.org/data/definitions/633.html) | Token Impersonation | Medium | [T1134](https://attack.mitre.org/techniques/T1134/) | CWE-287, CWE-1270 |
| [CAPEC-634](https://capec.mitre.org/data/definitions/634.html) | Probe Audio and Video Peripherals | High | [T1123](https://attack.mitre.org/techniques/T1123/), [T1125](https://attack.mitre.org/techniques/T1125/) | CWE-267 |
| [CAPEC-635](https://capec.mitre.org/data/definitions/635.html) | Alternative Execution Due to Deceptive Filenames | High | [T1036.007](https://attack.mitre.org/techniques/T1036/007/) | CWE-162 |
| [CAPEC-636](https://capec.mitre.org/data/definitions/636.html) | Hiding Malicious Data or Code within Files | High | [T1001.002](https://attack.mitre.org/techniques/T1001/002/), [T1027.003](https://attack.mitre.org/techniques/T1027/003/), [T1027.004](https://attack.mitre.org/techniques/T1027/004/), [T1218.001](https://attack.mitre.org/techniques/T1218/001/), [T1221](https://attack.mitre.org/techniques/T1221/) | CWE-506 |
| [CAPEC-637](https://capec.mitre.org/data/definitions/637.html) | Collect Data from Clipboard | Low | [T1115](https://attack.mitre.org/techniques/T1115/) | CWE-267 |
| [CAPEC-638](https://capec.mitre.org/data/definitions/638.html) | Altered Component Firmware | Very High | [T1542.002](https://attack.mitre.org/techniques/T1542/002/) | — |
| [CAPEC-639](https://capec.mitre.org/data/definitions/639.html) | Probe System Files | Medium | [T1039](https://attack.mitre.org/techniques/T1039/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1552.003](https://attack.mitre.org/techniques/T1552/003/), [T1552.004](https://attack.mitre.org/techniques/T1552/004/), [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | CWE-552 |
| [CAPEC-640](https://capec.mitre.org/data/definitions/640.html) | Inclusion of Code in Existing Process | High | [T1505.005](https://attack.mitre.org/techniques/T1505/005/), [T1574.006](https://attack.mitre.org/techniques/T1574/006/), [T1574.013](https://attack.mitre.org/techniques/T1574/013/), [T1620](https://attack.mitre.org/techniques/T1620/) | CWE-114, CWE-829 |
| [CAPEC-641](https://capec.mitre.org/data/definitions/641.html) | DLL Side-Loading | High | [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | CWE-706 |
| [CAPEC-642](https://capec.mitre.org/data/definitions/642.html) | Replace Binaries | High | [T1505.005](https://attack.mitre.org/techniques/T1505/005/), [T1554](https://attack.mitre.org/techniques/T1554/), [T1574.005](https://attack.mitre.org/techniques/T1574/005/) | CWE-732 |
| [CAPEC-643](https://capec.mitre.org/data/definitions/643.html) | Identify Shared Files/Directories on System | Medium | [T1135](https://attack.mitre.org/techniques/T1135/) | CWE-267, CWE-200 |
| [CAPEC-644](https://capec.mitre.org/data/definitions/644.html) | Use of Captured Hashes (Pass The Hash) | High | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | CWE-522, CWE-836, CWE-308, CWE-294 |
| [CAPEC-645](https://capec.mitre.org/data/definitions/645.html) | Use of Captured Tickets (Pass The Ticket) | High | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | CWE-522, CWE-294, CWE-308 |
| [CAPEC-646](https://capec.mitre.org/data/definitions/646.html) | Peripheral Footprinting | Medium | [T1120](https://attack.mitre.org/techniques/T1120/) | CWE-200 |
| [CAPEC-647](https://capec.mitre.org/data/definitions/647.html) | Collect Data from Registries | Medium | [T1005](https://attack.mitre.org/techniques/T1005/), [T1012](https://attack.mitre.org/techniques/T1012/), [T1552.002](https://attack.mitre.org/techniques/T1552/002/) | CWE-285 |
| [CAPEC-648](https://capec.mitre.org/data/definitions/648.html) | Collect Data from Screen Capture | Medium | [T1113](https://attack.mitre.org/techniques/T1113/), [T1513](https://attack.mitre.org/techniques/T1513/) | CWE-267 |
| [CAPEC-649](https://capec.mitre.org/data/definitions/649.html) | Adding a Space to a File Extension | Medium | [T1036.006](https://attack.mitre.org/techniques/T1036/006/) | CWE-46 |
| [CAPEC-650](https://capec.mitre.org/data/definitions/650.html) | Upload a Web Shell to a Web Server | High | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | CWE-287, CWE-553 |
| [CAPEC-651](https://capec.mitre.org/data/definitions/651.html) | Eavesdropping | Medium | [T1111](https://attack.mitre.org/techniques/T1111/) | CWE-200 |
| [CAPEC-652](https://capec.mitre.org/data/definitions/652.html) | Use of Known Kerberos Credentials | High | [T1558](https://attack.mitre.org/techniques/T1558/) | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-654](https://capec.mitre.org/data/definitions/654.html) | Credential Prompt Impersonation | High | [T1056](https://attack.mitre.org/techniques/T1056/), [T1548.004](https://attack.mitre.org/techniques/T1548/004/) | CWE-1021 |
| [CAPEC-655](https://capec.mitre.org/data/definitions/655.html) | Avoid Security Tool Identification by Adding Data | High | [T1027.001](https://attack.mitre.org/techniques/T1027/001/) | — |
| [CAPEC-657](https://capec.mitre.org/data/definitions/657.html) | Malicious Automated Software Update via Spoofing | High | [T1072](https://attack.mitre.org/techniques/T1072/) | CWE-494 |
| [CAPEC-660](https://capec.mitre.org/data/definitions/660.html) | Root/Jailbreak Detection Evasion via Hooking | Very High | [T1055](https://attack.mitre.org/techniques/T1055/) | CWE-829 |
| [CAPEC-662](https://capec.mitre.org/data/definitions/662.html) | Adversary in the Browser (AiTB) | Very High | [T1185](https://attack.mitre.org/techniques/T1185/) | CWE-300, CWE-494 |
| [CAPEC-665](https://capec.mitre.org/data/definitions/665.html) | Exploitation of Thunderbolt Protection Flaws | Very High | [T1211](https://attack.mitre.org/techniques/T1211/), [T1542.002](https://attack.mitre.org/techniques/T1542/002/), [T1556](https://attack.mitre.org/techniques/T1556/) | CWE-345, CWE-353, CWE-288, CWE-1188 |
| [CAPEC-666](https://capec.mitre.org/data/definitions/666.html) | BlueSmacking | Medium | [T1498.001](https://attack.mitre.org/techniques/T1498/001/), [T1499.001](https://attack.mitre.org/techniques/T1499/001/) | CWE-404 |
| [CAPEC-668](https://capec.mitre.org/data/definitions/668.html) | Key Negotiation of Bluetooth Attack (KNOB) | High | [T1565.002](https://attack.mitre.org/techniques/T1565/002/) | CWE-425, CWE-285, CWE-693 |
| [CAPEC-669](https://capec.mitre.org/data/definitions/669.html) | Alteration of a Software Update | High | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | — |
| [CAPEC-670](https://capec.mitre.org/data/definitions/670.html) | Software Development Tools Maliciously Altered | High | [T1127](https://attack.mitre.org/techniques/T1127/), [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | — |
| [CAPEC-671](https://capec.mitre.org/data/definitions/671.html) | Requirements for ASIC Functionality Maliciously Altered | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-672](https://capec.mitre.org/data/definitions/672.html) | Malicious Code Implanted During Chip Programming | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-673](https://capec.mitre.org/data/definitions/673.html) | Developer Signing Maliciously Altered Software | High | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | — |
| [CAPEC-674](https://capec.mitre.org/data/definitions/674.html) | Design for FPGA Maliciously Altered | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-675](https://capec.mitre.org/data/definitions/675.html) | Retrieve Data from Decommissioned Devices | Medium | [T1052](https://attack.mitre.org/techniques/T1052/) | CWE-1266 |
| [CAPEC-677](https://capec.mitre.org/data/definitions/677.html) | Server Motherboard Compromise | High | [T1195.003](https://attack.mitre.org/techniques/T1195/003/) | — |
| [CAPEC-678](https://capec.mitre.org/data/definitions/678.html) | System Build Data Maliciously Altered | High | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | — |
| [CAPEC-691](https://capec.mitre.org/data/definitions/691.html) | Spoof Open-Source Software Metadata | High | [T1195.001](https://attack.mitre.org/techniques/T1195/001/), [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | CWE-494 |
| [CAPEC-694](https://capec.mitre.org/data/definitions/694.html) | System Location Discovery | Very Low | [T1614](https://attack.mitre.org/techniques/T1614/) | CWE-497 |
| [CAPEC-695](https://capec.mitre.org/data/definitions/695.html) | Repo Jacking | High | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | CWE-494, CWE-829 |
| [CAPEC-697](https://capec.mitre.org/data/definitions/697.html) | DHCP Spoofing | High | [T1557.003](https://attack.mitre.org/techniques/T1557/003/) | CWE-923 |
| [CAPEC-698](https://capec.mitre.org/data/definitions/698.html) | Install Malicious Extension | High | [T1176](https://attack.mitre.org/techniques/T1176/), [T1505.004](https://attack.mitre.org/techniques/T1505/004/) | CWE-507, CWE-829 |
| [CAPEC-700](https://capec.mitre.org/data/definitions/700.html) | Network Boundary Bridging | High | [T1599](https://attack.mitre.org/techniques/T1599/) | — |

---

## High-severity attack patterns

| CAPEC | Pattern | Likelihood | Related CWE |
|---|---|---|---|
| [CAPEC-1](https://capec.mitre.org/data/definitions/1.html) | Accessing Functionality Not Properly Constrained by ACLs | High | CWE-276, CWE-285, CWE-434, CWE-693 |
| [CAPEC-4](https://capec.mitre.org/data/definitions/4.html) | Using Alternative IP Address Encodings | Medium | CWE-291, CWE-173 |
| [CAPEC-5](https://capec.mitre.org/data/definitions/5.html) | Blue Boxing | Medium | CWE-285 |
| [CAPEC-6](https://capec.mitre.org/data/definitions/6.html) | Argument Injection | High | CWE-74, CWE-146, CWE-184, CWE-78 |
| [CAPEC-7](https://capec.mitre.org/data/definitions/7.html) | Blind SQL Injection | High | CWE-89, CWE-209, CWE-74, CWE-20 |
| [CAPEC-8](https://capec.mitre.org/data/definitions/8.html) | Buffer Overflow in an API Call | High | CWE-120, CWE-119, CWE-118, CWE-74 |
| [CAPEC-9](https://capec.mitre.org/data/definitions/9.html) | Buffer Overflow in Local Command-Line Utilities | High | CWE-120, CWE-118, CWE-119, CWE-74 |
| [CAPEC-10](https://capec.mitre.org/data/definitions/10.html) | Buffer Overflow via Environment Variables | High | CWE-120, CWE-302, CWE-118, CWE-119 |
| [CAPEC-11](https://capec.mitre.org/data/definitions/11.html) | Cause Web Server Misclassification | Medium | CWE-430 |
| [CAPEC-12](https://capec.mitre.org/data/definitions/12.html) | Choosing Message Identifier | High | CWE-201, CWE-306 |
| [CAPEC-13](https://capec.mitre.org/data/definitions/13.html) | Subverting Environment Variable Values | High | CWE-353, CWE-285, CWE-302, CWE-74 |
| [CAPEC-14](https://capec.mitre.org/data/definitions/14.html) | Client-side Injection-induced Buffer Overflow | Medium | CWE-120, CWE-353, CWE-118, CWE-119 |
| [CAPEC-15](https://capec.mitre.org/data/definitions/15.html) | Command Delimiters | High | CWE-146, CWE-77, CWE-184, CWE-78 |
| [CAPEC-16](https://capec.mitre.org/data/definitions/16.html) | Dictionary-based Password Attack | Medium | CWE-521, CWE-262, CWE-263, CWE-654 |
| [CAPEC-17](https://capec.mitre.org/data/definitions/17.html) | Using Malicious Files | High | CWE-732, CWE-285, CWE-272, CWE-59 |
| [CAPEC-18](https://capec.mitre.org/data/definitions/18.html) | XSS Targeting Non-Script Elements | High | CWE-80 |
| [CAPEC-19](https://capec.mitre.org/data/definitions/19.html) | Embedding Scripts within Scripts | High | CWE-284 |
| [CAPEC-21](https://capec.mitre.org/data/definitions/21.html) | Exploitation of Trusted Identifiers | High | CWE-290, CWE-302, CWE-346, CWE-539 |
| [CAPEC-22](https://capec.mitre.org/data/definitions/22.html) | Exploiting Trust in Client | High | CWE-290, CWE-287, CWE-20, CWE-200 |
| [CAPEC-23](https://capec.mitre.org/data/definitions/23.html) | File Content Injection | High | CWE-20 |
| [CAPEC-24](https://capec.mitre.org/data/definitions/24.html) | Filter Failure through Buffer Overflow | High | CWE-120, CWE-119, CWE-118, CWE-74 |
| [CAPEC-25](https://capec.mitre.org/data/definitions/25.html) | Forced Deadlock | Low | CWE-412, CWE-567, CWE-662, CWE-667 |
| [CAPEC-26](https://capec.mitre.org/data/definitions/26.html) | Leveraging Race Conditions | High | CWE-368, CWE-363, CWE-366, CWE-370 |
| [CAPEC-27](https://capec.mitre.org/data/definitions/27.html) | Leveraging Race Conditions via Symbolic Links | Medium | CWE-367, CWE-61, CWE-662, CWE-689 |
| [CAPEC-29](https://capec.mitre.org/data/definitions/29.html) | Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions | High | CWE-367, CWE-368, CWE-366, CWE-370 |
| [CAPEC-30](https://capec.mitre.org/data/definitions/30.html) | Hijacking a Privileged Thread of Execution | Low | CWE-270 |
| [CAPEC-31](https://capec.mitre.org/data/definitions/31.html) | Accessing/Intercepting/Modifying HTTP Cookies | High | CWE-565, CWE-302, CWE-311, CWE-113 |
| [CAPEC-32](https://capec.mitre.org/data/definitions/32.html) | XSS Through HTTP Query Strings | High | CWE-80 |
| [CAPEC-33](https://capec.mitre.org/data/definitions/33.html) | HTTP Request Smuggling | Medium | CWE-444 |
| [CAPEC-34](https://capec.mitre.org/data/definitions/34.html) | HTTP Response Splitting | Medium | CWE-74, CWE-113, CWE-138, CWE-436 |
| [CAPEC-35](https://capec.mitre.org/data/definitions/35.html) | Leverage Executable Code in Non-Executable Files | High | CWE-94, CWE-96, CWE-95, CWE-97 |
| [CAPEC-36](https://capec.mitre.org/data/definitions/36.html) | Using Unpublished Interfaces or Functionality | Medium | CWE-306, CWE-693, CWE-695, CWE-1242 |
| [CAPEC-37](https://capec.mitre.org/data/definitions/37.html) | Retrieve Embedded Sensitive Data | High | CWE-226, CWE-311, CWE-525, CWE-312 |
| [CAPEC-38](https://capec.mitre.org/data/definitions/38.html) | Leveraging/Manipulating Configuration File Search Paths | High | CWE-426, CWE-427 |
| [CAPEC-40](https://capec.mitre.org/data/definitions/40.html) | Manipulating Writeable Terminal Devices | High | CWE-77 |
| [CAPEC-41](https://capec.mitre.org/data/definitions/41.html) | Using Meta-characters in E-mail Headers to Inject Malicious Payloads | High | CWE-150, CWE-88, CWE-697 |
| [CAPEC-42](https://capec.mitre.org/data/definitions/42.html) | MIME Conversion | High | CWE-120, CWE-119, CWE-74, CWE-20 |
| [CAPEC-43](https://capec.mitre.org/data/definitions/43.html) | Exploiting Multiple Input Interpretation Layers | Medium | CWE-179, CWE-181, CWE-184, CWE-183 |
| [CAPEC-44](https://capec.mitre.org/data/definitions/44.html) | Overflow Binary Resource File | High | CWE-120, CWE-119, CWE-697 |
| [CAPEC-45](https://capec.mitre.org/data/definitions/45.html) | Buffer Overflow via Symbolic Links | High | CWE-120, CWE-285, CWE-302, CWE-118 |
| [CAPEC-46](https://capec.mitre.org/data/definitions/46.html) | Overflow Variables and Tags | High | CWE-120, CWE-118, CWE-119, CWE-74 |
| [CAPEC-47](https://capec.mitre.org/data/definitions/47.html) | Buffer Overflow via Parameter Expansion | Medium | CWE-120, CWE-119, CWE-118, CWE-130 |
| [CAPEC-48](https://capec.mitre.org/data/definitions/48.html) | Passing Local Filenames to Functions That Expect a URL | High | CWE-241, CWE-706 |
| [CAPEC-49](https://capec.mitre.org/data/definitions/49.html) | Password Brute Forcing | Medium | CWE-521, CWE-262, CWE-263, CWE-257 |
| [CAPEC-50](https://capec.mitre.org/data/definitions/50.html) | Password Recovery Exploitation | Medium | CWE-522, CWE-640 |
| [CAPEC-51](https://capec.mitre.org/data/definitions/51.html) | Poison Web Service Registry | High | CWE-285, CWE-74, CWE-693 |
| [CAPEC-52](https://capec.mitre.org/data/definitions/52.html) | Embedding NULL Bytes | High | CWE-158, CWE-172, CWE-173, CWE-74 |
| [CAPEC-53](https://capec.mitre.org/data/definitions/53.html) | Postfix, Null Terminate, and Backslash | High | CWE-158, CWE-172, CWE-173, CWE-74 |
| [CAPEC-57](https://capec.mitre.org/data/definitions/57.html) | Utilizing REST's Trust in the System Resource to Obtain Sensitive Data | Medium | CWE-300, CWE-287, CWE-693 |
| [CAPEC-58](https://capec.mitre.org/data/definitions/58.html) | Restful Privilege Elevation | High | CWE-267, CWE-269 |
| [CAPEC-59](https://capec.mitre.org/data/definitions/59.html) | Session Credential Falsification through Prediction | High | CWE-290, CWE-330, CWE-331, CWE-346 |
| [CAPEC-60](https://capec.mitre.org/data/definitions/60.html) | Reusing Session IDs (aka Session Replay) | High | CWE-294, CWE-290, CWE-346, CWE-384 |
| [CAPEC-61](https://capec.mitre.org/data/definitions/61.html) | Session Fixation | Medium | CWE-384, CWE-664, CWE-732 |
| [CAPEC-62](https://capec.mitre.org/data/definitions/62.html) | Cross Site Request Forgery | High | CWE-352, CWE-306, CWE-664, CWE-732 |
| [CAPEC-63](https://capec.mitre.org/data/definitions/63.html) | Cross-Site Scripting (XSS) | High | CWE-79, CWE-20 |
| [CAPEC-64](https://capec.mitre.org/data/definitions/64.html) | Using Slashes and URL Encoding Combined to Bypass Validation Logic | High | CWE-177, CWE-173, CWE-172, CWE-73 |
| [CAPEC-65](https://capec.mitre.org/data/definitions/65.html) | Sniff Application Code | Low | CWE-319, CWE-311, CWE-318, CWE-693 |
| [CAPEC-66](https://capec.mitre.org/data/definitions/66.html) | SQL Injection | High | CWE-89, CWE-1286 |
| [CAPEC-67](https://capec.mitre.org/data/definitions/67.html) | String Format Overflow in syslog() | High | CWE-120, CWE-134, CWE-74, CWE-20 |
| [CAPEC-68](https://capec.mitre.org/data/definitions/68.html) | Subvert Code-signing Facilities | Low | CWE-325, CWE-328, CWE-1326 |
| [CAPEC-69](https://capec.mitre.org/data/definitions/69.html) | Target Programs with Elevated Privileges | High | CWE-250, CWE-15 |
| [CAPEC-70](https://capec.mitre.org/data/definitions/70.html) | Try Common or Default Usernames and Passwords | Medium | CWE-521, CWE-262, CWE-263, CWE-798 |
| [CAPEC-71](https://capec.mitre.org/data/definitions/71.html) | Using Unicode Encoding to Bypass Validation Logic | Medium | CWE-176, CWE-179, CWE-180, CWE-173 |
| [CAPEC-72](https://capec.mitre.org/data/definitions/72.html) | URL Encoding | High | CWE-173, CWE-177, CWE-172, CWE-73 |
| [CAPEC-73](https://capec.mitre.org/data/definitions/73.html) | User-Controlled Filename | High | CWE-20, CWE-184, CWE-96, CWE-348 |
| [CAPEC-74](https://capec.mitre.org/data/definitions/74.html) | Manipulating State | Medium | CWE-372, CWE-315, CWE-353, CWE-693 |
| [CAPEC-75](https://capec.mitre.org/data/definitions/75.html) | Manipulating Writeable Configuration Files | High | CWE-349, CWE-99, CWE-77, CWE-346 |
| [CAPEC-76](https://capec.mitre.org/data/definitions/76.html) | Manipulating Web Input to File System Calls | High | CWE-23, CWE-22, CWE-73, CWE-77 |
| [CAPEC-77](https://capec.mitre.org/data/definitions/77.html) | Manipulating User-Controlled Variables | High | CWE-15, CWE-94, CWE-96, CWE-285 |
| [CAPEC-78](https://capec.mitre.org/data/definitions/78.html) | Using Escaped Slashes in Alternate Encoding | High | CWE-180, CWE-181, CWE-173, CWE-172 |
| [CAPEC-79](https://capec.mitre.org/data/definitions/79.html) | Using Slashes in Alternate Encoding | High | CWE-173, CWE-180, CWE-181, CWE-20 |
| [CAPEC-80](https://capec.mitre.org/data/definitions/80.html) | Using UTF-8 Encoding to Bypass Validation Logic | High | CWE-173, CWE-172, CWE-180, CWE-181 |
| [CAPEC-81](https://capec.mitre.org/data/definitions/81.html) | Web Server Logs Tampering | Medium | CWE-117, CWE-93, CWE-75, CWE-221 |
| [CAPEC-83](https://capec.mitre.org/data/definitions/83.html) | XPath Injection | High | CWE-91, CWE-74, CWE-20, CWE-707 |
| [CAPEC-84](https://capec.mitre.org/data/definitions/84.html) | XQuery Injection | High | CWE-74, CWE-707 |
| [CAPEC-86](https://capec.mitre.org/data/definitions/86.html) | XSS Through HTTP Headers | High | CWE-80 |
| [CAPEC-87](https://capec.mitre.org/data/definitions/87.html) | Forceful Browsing | High | CWE-425, CWE-285, CWE-693 |
| [CAPEC-88](https://capec.mitre.org/data/definitions/88.html) | OS Command Injection | High | CWE-78, CWE-88, CWE-20, CWE-697 |
| [CAPEC-89](https://capec.mitre.org/data/definitions/89.html) | Pharming | High | CWE-346, CWE-350 |
| [CAPEC-90](https://capec.mitre.org/data/definitions/90.html) | Reflection Attack in Authentication Protocol | High | CWE-301, CWE-303 |
| [CAPEC-92](https://capec.mitre.org/data/definitions/92.html) | Forced Integer Overflow | High | CWE-190, CWE-128, CWE-120, CWE-122 |
| [CAPEC-93](https://capec.mitre.org/data/definitions/93.html) | Log Injection-Tampering-Forging | High | CWE-117, CWE-75, CWE-150 |
| [CAPEC-94](https://capec.mitre.org/data/definitions/94.html) | Adversary in the Middle (AiTM) | High | CWE-300, CWE-290, CWE-593, CWE-287 |
| [CAPEC-95](https://capec.mitre.org/data/definitions/95.html) | WSDL Scanning | High | CWE-538 |
| [CAPEC-97](https://capec.mitre.org/data/definitions/97.html) | Cryptanalysis | Low | CWE-327, CWE-1204, CWE-1240, CWE-1241 |
| [CAPEC-98](https://capec.mitre.org/data/definitions/98.html) | Phishing | High | CWE-451 |
| [CAPEC-100](https://capec.mitre.org/data/definitions/100.html) | Overflow Buffers | High | CWE-120, CWE-119, CWE-131, CWE-129 |
| [CAPEC-101](https://capec.mitre.org/data/definitions/101.html) | Server Side Include (SSI) Injection | High | CWE-97, CWE-74, CWE-20 |
| [CAPEC-102](https://capec.mitre.org/data/definitions/102.html) | Session Sidejacking | High | CWE-294, CWE-522, CWE-523, CWE-319 |
| [CAPEC-103](https://capec.mitre.org/data/definitions/103.html) | Clickjacking | Medium | CWE-1021 |
| [CAPEC-104](https://capec.mitre.org/data/definitions/104.html) | Cross Zone Scripting | Medium | CWE-250, CWE-638, CWE-285, CWE-116 |
| [CAPEC-105](https://capec.mitre.org/data/definitions/105.html) | HTTP Request Splitting | Medium | CWE-74, CWE-113, CWE-138, CWE-436 |
| [CAPEC-107](https://capec.mitre.org/data/definitions/107.html) | Cross Site Tracing | Medium | CWE-693, CWE-648 |
| [CAPEC-108](https://capec.mitre.org/data/definitions/108.html) | Command Line Execution through SQL Injection | Low | CWE-89, CWE-74, CWE-20, CWE-78 |
| [CAPEC-109](https://capec.mitre.org/data/definitions/109.html) | Object Relational Mapping Injection | Low | CWE-20, CWE-89, CWE-564 |
| [CAPEC-110](https://capec.mitre.org/data/definitions/110.html) | SQL Injection through SOAP Parameter Tampering | High | CWE-89, CWE-20 |
| [CAPEC-111](https://capec.mitre.org/data/definitions/111.html) | JSON Hijacking (aka JavaScript Hijacking) | High | CWE-345, CWE-346, CWE-352 |
| [CAPEC-112](https://capec.mitre.org/data/definitions/112.html) | Brute Force | — | CWE-330, CWE-326, CWE-521 |
| [CAPEC-121](https://capec.mitre.org/data/definitions/121.html) | Exploit Non-Production Interfaces | Low | CWE-489, CWE-1209, CWE-1259, CWE-1267 |
| [CAPEC-123](https://capec.mitre.org/data/definitions/123.html) | Buffer Manipulation | High | CWE-119 |
| [CAPEC-126](https://capec.mitre.org/data/definitions/126.html) | Path Traversal | High | CWE-22 |
| [CAPEC-132](https://capec.mitre.org/data/definitions/132.html) | Symlink Attack | Low | CWE-59 |
| [CAPEC-135](https://capec.mitre.org/data/definitions/135.html) | Format String Injection | High | CWE-134, CWE-20, CWE-74 |
| [CAPEC-136](https://capec.mitre.org/data/definitions/136.html) | LDAP Injection | High | CWE-77, CWE-90, CWE-20 |
| [CAPEC-138](https://capec.mitre.org/data/definitions/138.html) | Reflection Injection | — | CWE-470 |
| [CAPEC-139](https://capec.mitre.org/data/definitions/139.html) | Relative Path Traversal | High | CWE-23 |
| [CAPEC-141](https://capec.mitre.org/data/definitions/141.html) | Cache Poisoning | High | CWE-348, CWE-345, CWE-349, CWE-346 |
| [CAPEC-142](https://capec.mitre.org/data/definitions/142.html) | DNS Cache Poisoning | High | CWE-348, CWE-345, CWE-349, CWE-346 |
| [CAPEC-146](https://capec.mitre.org/data/definitions/146.html) | XML Schema Poisoning | Low | CWE-15, CWE-472 |
| [CAPEC-159](https://capec.mitre.org/data/definitions/159.html) | Redirect Access to Libraries | High | CWE-706 |
| [CAPEC-161](https://capec.mitre.org/data/definitions/161.html) | Infrastructure Manipulation | — | CWE-923 |
| [CAPEC-162](https://capec.mitre.org/data/definitions/162.html) | Manipulating Hidden Fields | — | CWE-602 |
| [CAPEC-163](https://capec.mitre.org/data/definitions/163.html) | Spear Phishing | High | CWE-451 |
| [CAPEC-164](https://capec.mitre.org/data/definitions/164.html) | Mobile Phishing | High | CWE-451 |
| [CAPEC-173](https://capec.mitre.org/data/definitions/173.html) | Action Spoofing | High | CWE-451 |
| [CAPEC-175](https://capec.mitre.org/data/definitions/175.html) | Code Inclusion | Medium | CWE-829 |
| [CAPEC-177](https://capec.mitre.org/data/definitions/177.html) | Create files with the same name as files protected with a higher classification | — | CWE-706 |
| [CAPEC-185](https://capec.mitre.org/data/definitions/185.html) | Malicious Software Download | — | CWE-494 |
| [CAPEC-186](https://capec.mitre.org/data/definitions/186.html) | Malicious Software Update | — | CWE-494 |
| [CAPEC-187](https://capec.mitre.org/data/definitions/187.html) | Malicious Automated Software Update via Redirection | High | CWE-494 |
| [CAPEC-193](https://capec.mitre.org/data/definitions/193.html) | PHP Remote File Inclusion | High | CWE-98, CWE-80 |
| [CAPEC-199](https://capec.mitre.org/data/definitions/199.html) | XSS Using Alternate Syntax | High | CWE-87 |
| [CAPEC-201](https://capec.mitre.org/data/definitions/201.html) | Serialized Data External Linking | High | CWE-829 |
| [CAPEC-206](https://capec.mitre.org/data/definitions/206.html) | Signing Malicious Code | — | CWE-732 |
| [CAPEC-207](https://capec.mitre.org/data/definitions/207.html) | Removing Important Client Functionality | Medium | CWE-602 |
| [CAPEC-222](https://capec.mitre.org/data/definitions/222.html) | iFrame Overlay | Medium | CWE-1021 |
| [CAPEC-229](https://capec.mitre.org/data/definitions/229.html) | Serialized Data Parameter Blowup | High | CWE-770 |
| [CAPEC-230](https://capec.mitre.org/data/definitions/230.html) | Serialized Data with Nested Payloads | Medium | CWE-112, CWE-20, CWE-674, CWE-770 |
| [CAPEC-231](https://capec.mitre.org/data/definitions/231.html) | Oversized Serialized Data Payloads | Medium | CWE-112, CWE-20, CWE-674, CWE-770 |
| [CAPEC-237](https://capec.mitre.org/data/definitions/237.html) | Escaping a Sandbox by Calling Code in Another Language | Low | CWE-693 |
| [CAPEC-240](https://capec.mitre.org/data/definitions/240.html) | Resource Injection | High | CWE-99 |
| [CAPEC-242](https://capec.mitre.org/data/definitions/242.html) | Code Injection | High | CWE-94 |
| [CAPEC-244](https://capec.mitre.org/data/definitions/244.html) | XSS Targeting URI Placeholders | High | CWE-83 |
| [CAPEC-248](https://capec.mitre.org/data/definitions/248.html) | Command Injection | Medium | CWE-77 |
| [CAPEC-256](https://capec.mitre.org/data/definitions/256.html) | SOAP Array Overflow | — | CWE-805 |
| [CAPEC-267](https://capec.mitre.org/data/definitions/267.html) | Leverage Alternate Encoding | High | CWE-173, CWE-172, CWE-180, CWE-181 |
| [CAPEC-271](https://capec.mitre.org/data/definitions/271.html) | Schema Poisoning | Low | CWE-15 |
| [CAPEC-273](https://capec.mitre.org/data/definitions/273.html) | HTTP Response Smuggling | Medium | CWE-74, CWE-436, CWE-444 |
| [CAPEC-275](https://capec.mitre.org/data/definitions/275.html) | DNS Rebinding | High | CWE-350 |
| [CAPEC-279](https://capec.mitre.org/data/definitions/279.html) | SOAP Manipulation | Medium | CWE-707 |
| [CAPEC-401](https://capec.mitre.org/data/definitions/401.html) | Physically Hacking Hardware | Low | CWE-1263 |
| [CAPEC-440](https://capec.mitre.org/data/definitions/440.html) | Hardware Integrity Attack | Low | — |
| [CAPEC-441](https://capec.mitre.org/data/definitions/441.html) | Malicious Logic Insertion | Medium | CWE-284 |
| [CAPEC-442](https://capec.mitre.org/data/definitions/442.html) | Infected Software | Medium | CWE-506 |
| [CAPEC-443](https://capec.mitre.org/data/definitions/443.html) | Malicious Logic Inserted Into Product by Authorized Developer | Medium | — |
| [CAPEC-444](https://capec.mitre.org/data/definitions/444.html) | Development Alteration | Medium | — |
| [CAPEC-445](https://capec.mitre.org/data/definitions/445.html) | Malicious Logic Insertion into Product Software via Configuration Management Manipulation | Medium | — |
| [CAPEC-446](https://capec.mitre.org/data/definitions/446.html) | Malicious Logic Insertion into Product via Inclusion of Third-Party Component | Medium | — |
| [CAPEC-447](https://capec.mitre.org/data/definitions/447.html) | Design Alteration | Medium | — |
| [CAPEC-448](https://capec.mitre.org/data/definitions/448.html) | Embed Virus into DLL | Medium | CWE-506 |
| [CAPEC-452](https://capec.mitre.org/data/definitions/452.html) | Infected Hardware | Medium | — |
| [CAPEC-456](https://capec.mitre.org/data/definitions/456.html) | Infected Memory | Medium | CWE-1257, CWE-1260, CWE-1274, CWE-1312 |
| [CAPEC-457](https://capec.mitre.org/data/definitions/457.html) | USB Memory Attacks | Low | CWE-1299 |
| [CAPEC-459](https://capec.mitre.org/data/definitions/459.html) | Creating a Rogue Certification Authority Certificate | Medium | CWE-327, CWE-295, CWE-290 |
| [CAPEC-461](https://capec.mitre.org/data/definitions/461.html) | Web Services API Signature Forgery Leveraging Hash Function Extension Weakness | — | CWE-328, CWE-290 |
| [CAPEC-463](https://capec.mitre.org/data/definitions/463.html) | Padding Oracle Crypto Attack | — | CWE-209, CWE-514, CWE-649, CWE-347 |
| [CAPEC-470](https://capec.mitre.org/data/definitions/470.html) | Expanding Control over the Operating System from the Database | — | CWE-250, CWE-89 |
| [CAPEC-474](https://capec.mitre.org/data/definitions/474.html) | Signature Spoofing by Key Theft | Medium | CWE-522 |
| [CAPEC-475](https://capec.mitre.org/data/definitions/475.html) | Signature Spoofing by Improper Validation | Low | CWE-347, CWE-327, CWE-295 |
| [CAPEC-476](https://capec.mitre.org/data/definitions/476.html) | Signature Spoofing by Misrepresentation | Low | CWE-290 |
| [CAPEC-477](https://capec.mitre.org/data/definitions/477.html) | Signature Spoofing by Mixing Signed and Unsigned Content | Low | CWE-693, CWE-311, CWE-319 |
| [CAPEC-478](https://capec.mitre.org/data/definitions/478.html) | Modification of Windows Service Configuration | Low | CWE-284 |
| [CAPEC-480](https://capec.mitre.org/data/definitions/480.html) | Escaping Virtualization | Low | CWE-693 |
| [CAPEC-481](https://capec.mitre.org/data/definitions/481.html) | Contradictory Destinations in Traffic Routing Schemes | Medium | CWE-923 |
| [CAPEC-485](https://capec.mitre.org/data/definitions/485.html) | Signature Spoofing by Key Recreation | Low | CWE-330 |
| [CAPEC-504](https://capec.mitre.org/data/definitions/504.html) | Task Impersonation | Medium | CWE-1021 |
| [CAPEC-508](https://capec.mitre.org/data/definitions/508.html) | Shoulder Surfing | High | CWE-200, CWE-359 |
| [CAPEC-509](https://capec.mitre.org/data/definitions/509.html) | Kerberoasting | — | CWE-522, CWE-308, CWE-309, CWE-294 |
| [CAPEC-511](https://capec.mitre.org/data/definitions/511.html) | Infiltration of Software Development Environment | Low | — |
| [CAPEC-516](https://capec.mitre.org/data/definitions/516.html) | Hardware Component Substitution During Baselining | Low | — |
| [CAPEC-517](https://capec.mitre.org/data/definitions/517.html) | Documentation Alteration to Circumvent Dial-down | Low | — |
| [CAPEC-518](https://capec.mitre.org/data/definitions/518.html) | Documentation Alteration to Produce Under-performing Systems | Low | — |
| [CAPEC-519](https://capec.mitre.org/data/definitions/519.html) | Documentation Alteration to Cause Errors in System Design | Low | — |
| [CAPEC-520](https://capec.mitre.org/data/definitions/520.html) | Counterfeit Hardware Component Inserted During Product Assembly | Low | — |
| [CAPEC-521](https://capec.mitre.org/data/definitions/521.html) | Hardware Design Specifications Are Altered | Low | — |
| [CAPEC-522](https://capec.mitre.org/data/definitions/522.html) | Malicious Hardware Component Replacement | Low | — |
| [CAPEC-523](https://capec.mitre.org/data/definitions/523.html) | Malicious Software Implanted | Low | — |
| [CAPEC-524](https://capec.mitre.org/data/definitions/524.html) | Rogue Integration Procedures | Low | — |
| [CAPEC-530](https://capec.mitre.org/data/definitions/530.html) | Provide Counterfeit Component | Low | — |
| [CAPEC-531](https://capec.mitre.org/data/definitions/531.html) | Hardware Component Substitution | Low | — |
| [CAPEC-532](https://capec.mitre.org/data/definitions/532.html) | Altered Installed BIOS | Low | — |
| [CAPEC-533](https://capec.mitre.org/data/definitions/533.html) | Malicious Manual Software Update | Low | CWE-494 |
| [CAPEC-534](https://capec.mitre.org/data/definitions/534.html) | Malicious Hardware Update | Low | — |
| [CAPEC-535](https://capec.mitre.org/data/definitions/535.html) | Malicious Gray Market Hardware | Low | — |
| [CAPEC-536](https://capec.mitre.org/data/definitions/536.html) | Data Injected During Configuration | Low | CWE-284 |
| [CAPEC-537](https://capec.mitre.org/data/definitions/537.html) | Infiltration of Hardware Development Environment | Low | — |
| [CAPEC-538](https://capec.mitre.org/data/definitions/538.html) | Open-Source Library Manipulation | Low | CWE-494, CWE-829 |
| [CAPEC-539](https://capec.mitre.org/data/definitions/539.html) | ASIC With Malicious Functionality | Low | — |
| [CAPEC-540](https://capec.mitre.org/data/definitions/540.html) | Overread Buffers | Low | CWE-125 |
| [CAPEC-543](https://capec.mitre.org/data/definitions/543.html) | Counterfeit Websites | — | — |
| [CAPEC-544](https://capec.mitre.org/data/definitions/544.html) | Counterfeit Organizations | — | — |
| [CAPEC-548](https://capec.mitre.org/data/definitions/548.html) | Contaminate Resource | Low | — |
| [CAPEC-549](https://capec.mitre.org/data/definitions/549.html) | Local Execution of Code | Medium | CWE-829 |
| [CAPEC-552](https://capec.mitre.org/data/definitions/552.html) | Install Rootkit  | Medium | CWE-284 |
| [CAPEC-554](https://capec.mitre.org/data/definitions/554.html) | Functionality Bypass | Medium | CWE-424, CWE-1299 |
| [CAPEC-555](https://capec.mitre.org/data/definitions/555.html) | Remote Services with Stolen Credentials | — | CWE-522, CWE-308, CWE-309, CWE-294 |
| [CAPEC-558](https://capec.mitre.org/data/definitions/558.html) | Replace Trusted Executable | Low | CWE-284 |
| [CAPEC-559](https://capec.mitre.org/data/definitions/559.html) | Orbital Jamming | Low | — |
| [CAPEC-560](https://capec.mitre.org/data/definitions/560.html) | Use of Known Domain Credentials | High | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-565](https://capec.mitre.org/data/definitions/565.html) | Password Spraying | High | CWE-521, CWE-262, CWE-263, CWE-654 |
| [CAPEC-568](https://capec.mitre.org/data/definitions/568.html) | Capture Credentials via Keylogger | — | — |
| [CAPEC-582](https://capec.mitre.org/data/definitions/582.html) | Route Disabling | Low | — |
| [CAPEC-586](https://capec.mitre.org/data/definitions/586.html) | Object Injection | Medium | CWE-502 |
| [CAPEC-587](https://capec.mitre.org/data/definitions/587.html) | Cross Frame Scripting (XFS) | — | CWE-1021 |
| [CAPEC-588](https://capec.mitre.org/data/definitions/588.html) | DOM-Based XSS | High | CWE-79, CWE-20, CWE-83 |
| [CAPEC-590](https://capec.mitre.org/data/definitions/590.html) | IP Address Blocking | Low | CWE-300 |
| [CAPEC-591](https://capec.mitre.org/data/definitions/591.html) | Reflected XSS | High | CWE-79 |
| [CAPEC-592](https://capec.mitre.org/data/definitions/592.html) | Stored XSS | High | CWE-79 |
| [CAPEC-593](https://capec.mitre.org/data/definitions/593.html) | Session Hijacking | High | CWE-287 |
| [CAPEC-599](https://capec.mitre.org/data/definitions/599.html) | Terrestrial Jamming | Low | — |
| [CAPEC-600](https://capec.mitre.org/data/definitions/600.html) | Credential Stuffing | High | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-601](https://capec.mitre.org/data/definitions/601.html) | Jamming | Medium | — |
| [CAPEC-603](https://capec.mitre.org/data/definitions/603.html) | Blockage | Medium | — |
| [CAPEC-604](https://capec.mitre.org/data/definitions/604.html) | Wi-Fi Jamming | Medium | — |
| [CAPEC-606](https://capec.mitre.org/data/definitions/606.html) | Weakening of Cellular Encryption | — | CWE-757 |
| [CAPEC-608](https://capec.mitre.org/data/definitions/608.html) | Cryptanalysis of Cellular Encryption | — | CWE-327 |
| [CAPEC-610](https://capec.mitre.org/data/definitions/610.html) | Cellular Data Injection | — | — |
| [CAPEC-614](https://capec.mitre.org/data/definitions/614.html) | Rooting SIM Cards | — | CWE-327 |
| [CAPEC-620](https://capec.mitre.org/data/definitions/620.html) | Drop Encryption Level | — | CWE-757 |
| [CAPEC-624](https://capec.mitre.org/data/definitions/624.html) | Hardware Fault Injection | Low | CWE-1247, CWE-1248, CWE-1256, CWE-1319 |
| [CAPEC-627](https://capec.mitre.org/data/definitions/627.html) | Counterfeit GPS Signals | Low | — |
| [CAPEC-628](https://capec.mitre.org/data/definitions/628.html) | Carry-Off GPS Attack | Low | — |
| [CAPEC-634](https://capec.mitre.org/data/definitions/634.html) | Probe Audio and Video Peripherals | Low | CWE-267 |
| [CAPEC-635](https://capec.mitre.org/data/definitions/635.html) | Alternative Execution Due to Deceptive Filenames | — | CWE-162 |
| [CAPEC-636](https://capec.mitre.org/data/definitions/636.html) | Hiding Malicious Data or Code within Files | — | CWE-506 |
| [CAPEC-638](https://capec.mitre.org/data/definitions/638.html) | Altered Component Firmware | Low | — |
| [CAPEC-640](https://capec.mitre.org/data/definitions/640.html) | Inclusion of Code in Existing Process | Low | CWE-114, CWE-829 |
| [CAPEC-641](https://capec.mitre.org/data/definitions/641.html) | DLL Side-Loading | Low | CWE-706 |
| [CAPEC-642](https://capec.mitre.org/data/definitions/642.html) | Replace Binaries | — | CWE-732 |
| [CAPEC-644](https://capec.mitre.org/data/definitions/644.html) | Use of Captured Hashes (Pass The Hash) | Medium | CWE-522, CWE-836, CWE-308, CWE-294 |
| [CAPEC-645](https://capec.mitre.org/data/definitions/645.html) | Use of Captured Tickets (Pass The Ticket) | Low | CWE-522, CWE-294, CWE-308 |
| [CAPEC-650](https://capec.mitre.org/data/definitions/650.html) | Upload a Web Shell to a Web Server | — | CWE-287, CWE-553 |
| [CAPEC-652](https://capec.mitre.org/data/definitions/652.html) | Use of Known Kerberos Credentials | Medium | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-653](https://capec.mitre.org/data/definitions/653.html) | Use of Known Operating System Credentials | High | CWE-522, CWE-307, CWE-308, CWE-309 |
| [CAPEC-654](https://capec.mitre.org/data/definitions/654.html) | Credential Prompt Impersonation | Medium | CWE-1021 |
| [CAPEC-655](https://capec.mitre.org/data/definitions/655.html) | Avoid Security Tool Identification by Adding Data | High | — |
| [CAPEC-656](https://capec.mitre.org/data/definitions/656.html) | Voice Phishing | High | — |
| [CAPEC-657](https://capec.mitre.org/data/definitions/657.html) | Malicious Automated Software Update via Spoofing | High | CWE-494 |
| [CAPEC-660](https://capec.mitre.org/data/definitions/660.html) | Root/Jailbreak Detection Evasion via Hooking | Medium | CWE-829 |
| [CAPEC-661](https://capec.mitre.org/data/definitions/661.html) | Root/Jailbreak Detection Evasion via Debugging | Medium | CWE-489 |
| [CAPEC-662](https://capec.mitre.org/data/definitions/662.html) | Adversary in the Browser (AiTB) | High | CWE-300, CWE-494 |
| [CAPEC-663](https://capec.mitre.org/data/definitions/663.html) | Exploitation of Transient Instruction Execution | Low | CWE-1037, CWE-1303, CWE-1264 |
| [CAPEC-664](https://capec.mitre.org/data/definitions/664.html) | Server Side Request Forgery | High | CWE-918, CWE-20 |
| [CAPEC-665](https://capec.mitre.org/data/definitions/665.html) | Exploitation of Thunderbolt Protection Flaws | Low | CWE-345, CWE-353, CWE-288, CWE-1188 |
| [CAPEC-667](https://capec.mitre.org/data/definitions/667.html) | Bluetooth Impersonation AttackS (BIAS) | Medium | CWE-290 |
| [CAPEC-668](https://capec.mitre.org/data/definitions/668.html) | Key Negotiation of Bluetooth Attack (KNOB) | Low | CWE-425, CWE-285, CWE-693 |
| [CAPEC-669](https://capec.mitre.org/data/definitions/669.html) | Alteration of a Software Update | Medium | — |
| [CAPEC-670](https://capec.mitre.org/data/definitions/670.html) | Software Development Tools Maliciously Altered | Low | — |
| [CAPEC-671](https://capec.mitre.org/data/definitions/671.html) | Requirements for ASIC Functionality Maliciously Altered | Low | — |
| [CAPEC-672](https://capec.mitre.org/data/definitions/672.html) | Malicious Code Implanted During Chip Programming | Low | — |
| [CAPEC-673](https://capec.mitre.org/data/definitions/673.html) | Developer Signing Maliciously Altered Software | Medium | — |
| [CAPEC-674](https://capec.mitre.org/data/definitions/674.html) | Design for FPGA Maliciously Altered | Low | — |
| [CAPEC-676](https://capec.mitre.org/data/definitions/676.html) | NoSQL Injection | High | CWE-943, CWE-1286 |
| [CAPEC-677](https://capec.mitre.org/data/definitions/677.html) | Server Motherboard Compromise | Low | — |
| [CAPEC-678](https://capec.mitre.org/data/definitions/678.html) | System Build Data Maliciously Altered | Low | — |
| [CAPEC-679](https://capec.mitre.org/data/definitions/679.html) | Exploitation of Improperly Configured or Implemented Memory Protections | Medium | CWE-1222, CWE-1252, CWE-1257, CWE-1260 |
| [CAPEC-680](https://capec.mitre.org/data/definitions/680.html) | Exploitation of Improperly Controlled Registers | Medium | CWE-1224, CWE-1231, CWE-1233, CWE-1262 |
| [CAPEC-681](https://capec.mitre.org/data/definitions/681.html) | Exploitation of Improperly Controlled Hardware Security Identifiers | Medium | CWE-1259, CWE-1267, CWE-1270, CWE-1294 |
| [CAPEC-682](https://capec.mitre.org/data/definitions/682.html) | Exploitation of Firmware or ROM Code with Unpatchable Vulnerabilities | Medium | CWE-1277, CWE-1310 |
| [CAPEC-690](https://capec.mitre.org/data/definitions/690.html) | Metadata Spoofing | Medium | — |
| [CAPEC-691](https://capec.mitre.org/data/definitions/691.html) | Spoof Open-Source Software Metadata | Medium | CWE-494 |
| [CAPEC-692](https://capec.mitre.org/data/definitions/692.html) | Spoof Version Control System Commit Metadata | Medium | CWE-494 |
| [CAPEC-693](https://capec.mitre.org/data/definitions/693.html) | StarJacking | Medium | CWE-494 |
| [CAPEC-695](https://capec.mitre.org/data/definitions/695.html) | Repo Jacking | Medium | CWE-494, CWE-829 |
| [CAPEC-696](https://capec.mitre.org/data/definitions/696.html) | Load Value Injection | Low | CWE-1342 |
| [CAPEC-697](https://capec.mitre.org/data/definitions/697.html) | DHCP Spoofing | Low | CWE-923 |
| [CAPEC-698](https://capec.mitre.org/data/definitions/698.html) | Install Malicious Extension | Medium | CWE-507, CWE-829 |
| [CAPEC-699](https://capec.mitre.org/data/definitions/699.html) | Eavesdropping on a Monitor | Medium | CWE-1300 |
| [CAPEC-700](https://capec.mitre.org/data/definitions/700.html) | Network Boundary Bridging | Medium | — |
| [CAPEC-701](https://capec.mitre.org/data/definitions/701.html) | Browser in the Middle (BiTM) | Medium | CWE-294, CWE-345 |

---

*Source: MITRE CAPEC (CSV export, 615 entries).*
