# CAPEC-550 — Install New Service

<a id="capec-550"></a>

**Abstraction:** Detailed  
**Status:** Draft  

When an operating system starts, it also starts programs called services or daemons. Adversaries may install a new service which will be executed at startup (on a Windows system, by modifying the registry). The service name may be disguised by using a name from a related operating system or benign software. Services are usually run with elevated privileges.

## Mapped ATT&CK techniques (1)

- [T1543 — Create or Modify System Process](/mitre/techniques/T1543.md) — Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.

## Related CWE (1)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) — The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Limit privileges of user accounts so new service creation can only be performed by authorized administrators.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
