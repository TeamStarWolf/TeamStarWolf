# D3FEND: Process Segment Execution Prevention

<a id="process-segment-execution-prevention"></a>

D3FEND tactic: Harden  
Digital artifacts: Process Segment  

Preventing execution of any address in a memory region other than the code segment.

## ATT&CK techniques countered (17)

- [T0820: Exploitation for Evasion](https://attack.mitre.org/techniques/T0820): neutralizes
- [T0866: Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866): neutralizes
- [T0874: Hooking](https://attack.mitre.org/techniques/T0874): neutralizes
- [T0890: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T0890): neutralizes
- [T0894: System Binary Proxy Execution](https://attack.mitre.org/techniques/T0894): neutralizes
- [T1033: System Owner/User Discovery](/mitre/techniques/T1033.md): neutralizes. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1055.012: Process Hollowing](/mitre/techniques/T1055-012.md): neutralizes. Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses.
- [T1056.004: Credential API Hooking](/mitre/techniques/T1056-004.md): neutralizes. Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials.
- [T1068: Exploitation for Privilege Escalation](/mitre/techniques/T1068.md): neutralizes. Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.
- [T1189: Drive-by Compromise](/mitre/techniques/T1189.md): neutralizes. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.
- [T1190: Exploit Public-Facing Application](/mitre/techniques/T1190.md): neutralizes. Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.
- [T1203: Exploitation for Client Execution](/mitre/techniques/T1203.md): neutralizes. Adversaries may exploit software vulnerabilities in client applications to execute code.
- [T1210: Exploitation of Remote Services](/mitre/techniques/T1210.md): neutralizes. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1211: Exploitation for Stealth](/mitre/techniques/T1211.md): neutralizes. Adversaries may exploit vulnerabilities to evade detection by hiding activity, suppressing logging, or operating within trusted or unmonitored components.
- [T1212: Exploitation for Credential Access](/mitre/techniques/T1212.md): neutralizes. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1218.013: Mavinject](/mitre/techniques/T1218-013.md): neutralizes. Adversaries may abuse mavinject.exe to proxy execution of malicious code.
- [T1620: Reflective Code Loading](/mitre/techniques/T1620.md): neutralizes. Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads.

## Related pages

- [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md), which also counters 17 of these techniques
- [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md), which also counters 11 of these techniques
- [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md), which also counters 11 of these techniques
- [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md), which also counters 8 of these techniques
- [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), which also counters 8 of these techniques
- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 5 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends](/case-studies/ZERO_DAY_MARKET_EVENTS.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
