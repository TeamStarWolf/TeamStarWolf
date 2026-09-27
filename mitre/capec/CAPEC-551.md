# CAPEC-551 — Modify Existing Service

<a id="capec-551"></a>

**Abstraction:** Detailed  
**Status:** Draft  

When an operating system starts, it also starts programs called services or daemons. Modifying existing services may break existing services or may enable services that are disabled/not commonly used.

## Mapped ATT&CK techniques (1)

- [T1543 — Create or Modify System Process](/mitre/techniques/T1543.md) — Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.

## Related CWE (2)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) — The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.
- [CWE-522 — Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) — The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Mitigations

- Limit privileges of user accounts so service changes can only be performed by authorized administrators. Also monitor any service changes that may occur inadvertently.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
