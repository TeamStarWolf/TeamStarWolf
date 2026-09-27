# CAPEC-35 — Leverage Executable Code in Non-Executable Files

<a id="capec-35"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type exploits a system's trust in configuration and resource files. When the executable loads the resource (such as an image file or configuration file) the attacker has modified the file to either execute malicious code directly or manipulate the target process (e.g. application server) to execute based on the malicious configuration parameters. Since systems are increasingly in

## Mapped ATT&CK techniques (3)

- [T1027.006 — HTML Smuggling](/mitre/techniques/T1027-006.md)
- [T1027.009 — Embedded Payloads](/mitre/techniques/T1027-009.md)
- [T1564.009 — Resource Forking](/mitre/techniques/T1564-009.md)

## Related CWE (8)

- [CWE-94 — Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
- [CWE-95 — Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)
- [CWE-97 — Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)
- [CWE-272 — Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html)
- [CWE-59 — Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-282 — Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)
- [CWE-270 — Privilege Context Switching Error](https://cwe.mitre.org/data/definitions/270.html)

## Prerequisites

- The attacker must have the ability to modify non-executable files consumed by the target software.

## Skills required

- To identify and execute against an over-privileged system interface:LEVEL:Low

## Mitigations

- Design: Enforce principle of least privilege
- Design: Run server interfaces with a non-root account and/or utilize chroot jails or other configuration techniques to constrain privileges even if attacker gains some limited access to commands.
- Imple

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
