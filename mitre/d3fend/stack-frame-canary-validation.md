# D3FEND: Stack Frame Canary Validation

<a id="stack-frame-canary-validation"></a>

D3FEND tactic: Harden  
Digital artifacts: Stack Frame  

Comparing a value stored in a stack frame with a known good value in order to prevent or detect a memory segment overwrite.

## ATT&CK techniques countered (8)

- [T0820](https://attack.mitre.org/techniques/T0820): validates
- [T0866](https://attack.mitre.org/techniques/T0866): validates
- [T0890](https://attack.mitre.org/techniques/T0890): validates
- [T1068: Exploitation for Privilege Escalation](/mitre/techniques/T1068.md): validates. Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.
- [T1203: Exploitation for Client Execution](/mitre/techniques/T1203.md): validates. Adversaries may exploit software vulnerabilities in client applications to execute code.
- [T1210: Exploitation of Remote Services](/mitre/techniques/T1210.md): validates. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1211: Exploitation for Stealth](/mitre/techniques/T1211.md): validates. Adversaries may exploit vulnerabilities to evade detection by hiding activity, suppressing logging, or operating within trusted or unmonitored components.
- [T1212: Exploitation for Credential Access](/mitre/techniques/T1212.md): validates. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
