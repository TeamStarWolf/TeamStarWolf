# CAPEC-546 — Incomplete Data Deletion in a Multi-Tenant Environment

<a id="capec-546"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Draft  

An adversary obtains unauthorized information due to insecure or incomplete data deletion in a multi-tenant environment. If a cloud provider fails to completely delete storage and data from former cloud tenants' systems/resources, once these resources are allocated to new, potentially malicious tenants, the latter can probe the provided resources for sensitive information still there.

## Related CWE (3)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html)
- [CWE-1272 — Sensitive Information Uncleared Before Debug/Power State Transition](https://cwe.mitre.org/data/definitions/1272.html)

## Prerequisites

- The cloud provider must not assuredly delete part or all of the sensitive data for which they are responsible.The adversary must have the ability to interact with the system.

## Skills required

- The adversary requires the ability to traverse directory structure.:LEVEL:Low

## Mitigations

- Cloud providers should completely delete data to render it irrecoverable and inaccessible from any layer and component of infrastructure resources.
- Deletion of data should be completed promptly when requested.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
