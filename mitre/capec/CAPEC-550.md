# CAPEC-550 — Install New Service

<a id="capec-550"></a>

**Abstraction:** Detailed  
**Typical severity:**   
**Likelihood:** 

When an operating system starts, it also starts programs called services or daemons. Adversaries may install a new service which will be executed at startup (on a Windows system, by modifying the registry). The service name may be disguised by using a name from a related operating system or benign software. Services are usually run with elevated privileges.

## Mapped ATT&CK techniques (1)

- [T1543](/mitre/techniques/T1543.md)

## Related CWE (1)

[CWE-284](/CWE_REFERENCE.md)

**Mitigations:** ::Limit privileges of user accounts so new service creation can only be performed by authorized administrators.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
