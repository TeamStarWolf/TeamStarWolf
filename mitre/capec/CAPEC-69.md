# CAPEC-69 — Target Programs with Elevated Privileges

<a id="capec-69"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

This attack targets programs running with elevated privileges. The adversary tries to leverage a vulnerability in the running program and get arbitrary code to execute with elevated privileges.

## Related CWE (2)

[CWE-250](/CWE_REFERENCE.md) [CWE-15](/CWE_REFERENCE.md)

**Prerequisites:** ::The targeted program runs with elevated OS privileges.::The targeted program accepts input data from the user or from another program.::The targeted program is giving away information about itself. 

**Skills required:** ::SKILL:An attacker can use a tool to scan and automatically launch an attack against known issues. A tool can also repeat a sequence of instructions 

**Mitigations:** ::Apply the principle of least privilege.::Validate all untrusted data.::Apply the latest patches.::Scan your services and disable the ones which are not needed and are exposed unnecessarily. Exposing programs increases the attack surface. Only expos


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
