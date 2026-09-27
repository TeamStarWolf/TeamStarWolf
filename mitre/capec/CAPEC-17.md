# CAPEC-17 — Using Malicious Files

<a id="capec-17"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type exploits a system's configuration that allows an adversary to either directly access an executable file, for example through shell access; or in a possible worst case allows an adversary to upload a file and then execute it. Web servers, ftp servers, and message oriented middleware systems which have many integration points are particularly vulnerable, because both the progr

## Mapped ATT&CK techniques (2)

- [T1574.005 — Executable Installer File Permissions Weakness](/mitre/techniques/T1574-005.md) — Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer.
- [T1574.010 — Services File Permissions Weakness](/mitre/techniques/T1574-010.md) — Adversaries may execute their own malicious payloads by hijacking the binaries used by services.

## Related CWE (7)

- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html) — The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) — The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-272 — Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html) — The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.
- [CWE-59 — Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html) — The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.
- [CWE-282 — Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html) — The product assigns the wrong ownership, or does not properly verify the ownership, of an object or resource.
- [CWE-270 — Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html) — The product does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) — The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

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
