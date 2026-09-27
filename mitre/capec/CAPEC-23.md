# CAPEC-23 — File Content Injection

<a id="capec-23"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

An adversary poisons files with a malicious payload (targeting the file systems accessible by the target software), which may be passed through by standard channels such as via email, and standard web content like PDF and multimedia files. The adversary exploits known vulnerabilities or handling routines in the target processes, in order to exploit the host's trust in executing remote content, inc

## Related CWE (1)

[CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::The target software must consume files.::The adversary must have access to modify files that the target software will consume.::

**Skills required:** ::SKILL:How to poison a file with malicious payload that will exploit a vulnerability when the file is opened. The adversary must also know how to pla

**Mitigations:** ::Design: Enforce principle of least privilege::Design: Validate all input for content including files. Ensure that if files and remote content must be accepted that once accepted, they are placed in a sandbox type location so that lower assurance cl


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
