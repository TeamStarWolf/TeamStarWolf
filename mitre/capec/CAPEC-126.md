# CAPEC-126 — Path Traversal

<a id="capec-126"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

An adversary uses path manipulation methods to exploit insufficient input validation of a target to obtain access to data that should be not be retrievable by ordinary well-formed requests. A typical variety of this attack involves specifying a path to a desired file together with dot-dot-slash characters, resulting in the file access API or function traversing out of the intended directory struct

## Related CWE (1)

[CWE-22](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must be able to control the path that is requested of the target.::The target must fail to adequately sanitize incoming paths::

**Skills required:** ::SKILL:Simple command line attacks or to inject the malicious payload in a web page.:LEVEL:Low::SKILL:Customizing attacks to bypass non trivial filte

**Mitigations:** ::Design: Configure the access control correctly.::Design: Enforce principle of least privilege.::Design: Execute programs with constrained privileges, so parent process does not open up further vulnerabilities. Ensure that all directories, temporary


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
