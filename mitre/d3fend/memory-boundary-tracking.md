# D3FEND: Memory Boundary Tracking

<a id="memory-boundary-tracking"></a>

D3FEND tactic: Detect  
Digital artifacts: Process Code Segment  

Analyzing a call stack for return addresses which point to unexpected  memory locations.

## ATT&CK techniques countered (11)

- [T0820: Exploitation for Evasion](https://attack.mitre.org/techniques/T0820): analyzes
- [T0866: Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866): analyzes
- [T0874: Hooking](https://attack.mitre.org/techniques/T0874): analyzes
- [T0890: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T0890): analyzes
- [T1055.012: Process Hollowing](/mitre/techniques/T1055-012.md): analyzes. Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses.
- [T1056.004: Credential API Hooking](/mitre/techniques/T1056-004.md): analyzes. Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials.
- [T1068: Exploitation for Privilege Escalation](/mitre/techniques/T1068.md): analyzes. Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.
- [T1203: Exploitation for Client Execution](/mitre/techniques/T1203.md): analyzes. Adversaries may exploit software vulnerabilities in client applications to execute code.
- [T1210: Exploitation of Remote Services](/mitre/techniques/T1210.md): analyzes. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1211: Exploitation for Stealth](/mitre/techniques/T1211.md): analyzes. Adversaries may exploit vulnerabilities to evade detection by hiding activity, suppressing logging, or operating within trusted or unmonitored components.
- [T1212: Exploitation for Credential Access](/mitre/techniques/T1212.md): analyzes. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.

## Related pages

- [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md), which also counters 11 of these techniques
- [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), which also counters 11 of these techniques
- [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md), which also counters 11 of these techniques
- [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md), which also counters 8 of these techniques
- [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), which also counters 8 of these techniques
- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 2 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Node.js, CVE-2026-111497: Version Check and Fix in the Lab](/case-studies/NODEJS_CVE_2026_111497.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
