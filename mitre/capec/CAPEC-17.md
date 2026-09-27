# CAPEC-17 — Using Malicious Files

<a id="capec-17"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type exploits a system's configuration that allows an adversary to either directly access an executable file, for example through shell access; or in a possible worst case allows an adversary to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the progr

## Mapped ATT&CK techniques (2)

- [T1574.005 — Executable Installer File Permissions Weakness](/mitre/techniques/T1574-005.md)
- [T1574.010 — Services File Permissions Weakness](/mitre/techniques/T1574-010.md)

## Related CWE (7)

- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-272 — Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html)
- [CWE-59 — Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-282 — Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)
- [CWE-270 — Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Prerequisites

- System's configuration must allow an attacker to directly access executable files or upload files to execute. This means that any access control system that is supposed to mediate communications bet

## Skills required

- To identify and execute against an over-privileged system interface:LEVEL:Low

## Mitigations

- Design: Enforce principle of least privilege
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Imple

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
