# D3FEND: Segment Address Offset Randomization

<a id="segment-address-offset-randomization"></a>

**D3FEND tactic:** Harden  
**Digital artifacts:** Process Segment  

Randomizing the base (start) address of one or more segments of memory during the initialization of a process.

## ATT&CK techniques countered (17)

- [T0820](https://attack.mitre.org/techniques/T0820) — obfuscates
- [T0866](https://attack.mitre.org/techniques/T0866) — obfuscates
- [T0874](https://attack.mitre.org/techniques/T0874) — obfuscates
- [T0890](https://attack.mitre.org/techniques/T0890) — obfuscates
- [T0894](https://attack.mitre.org/techniques/T0894) — obfuscates
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — obfuscates. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1055.012 — Process Hollowing](/mitre/techniques/T1055-012.md) — obfuscates. Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses.
- [T1056.004 — Credential API Hooking](/mitre/techniques/T1056-004.md) — obfuscates. Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials.
- [T1068 — Exploitation for Privilege Escalation](/mitre/techniques/T1068.md) — obfuscates. Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.
- [T1189 — Drive-by Compromise](/mitre/techniques/T1189.md) — obfuscates. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.
- [T1190 — Exploit Public-Facing Application](/mitre/techniques/T1190.md) — obfuscates. Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.
- [T1203 — Exploitation for Client Execution](/mitre/techniques/T1203.md) — obfuscates. Adversaries may exploit software vulnerabilities in client applications to execute code.
- [T1210 — Exploitation of Remote Services](/mitre/techniques/T1210.md) — obfuscates. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1211 — Exploitation for Stealth](/mitre/techniques/T1211.md) — obfuscates. Adversaries may exploit vulnerabilities to evade detection by hiding activity, suppressing logging, or operating within trusted or unmonitored components.
- [T1212 — Exploitation for Credential Access](/mitre/techniques/T1212.md) — obfuscates. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1218.013 — Mavinject](/mitre/techniques/T1218-013.md) — obfuscates. Adversaries may abuse mavinject.exe to proxy execution of malicious code.
- [T1620 — Reflective Code Loading](/mitre/techniques/T1620.md) — obfuscates. Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
