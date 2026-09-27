# CAPEC-252 — PHP Local File Inclusion

<a id="capec-252"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** 

The attacker loads and executes an arbitrary local PHP file on a target machine. The attacker could use this to try to load old versions of PHP files that have known vulnerabilities, to load PHP files that the attacker placed on the local machine during a prior attack, or to otherwise change the functionality of the targeted application in unexpected ways.

## Related CWE (1)

[CWE-829](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted PHP application must have a bug that allows an attacker to control which code file is loaded at some juncture.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
