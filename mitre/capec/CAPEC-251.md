# CAPEC-251 — Local Code Inclusion

<a id="capec-251"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** 

The attacker forces an application to load arbitrary code files from the local machine. The attacker could use this to try to load old versions of library files that have known vulnerabilities, to load files that the attacker placed on the local machine during a prior attack, or to otherwise change the functionality of the targeted application in unexpected ways.

## Mapped ATT&CK techniques (1)

- [T1055](/mitre/techniques/T1055.md)

## Related CWE (1)

[CWE-829](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted application must have a bug that allows an adversary to control which code file is loaded at some juncture.::Some variants of this attack may require that old versions of some code file

**Mitigations:** ::Implementation: Avoid passing user input to filesystem or framework API. If necessary to do so, implement a specific, allowlist approach.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
