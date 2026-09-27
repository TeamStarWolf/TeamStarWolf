# CAPEC-675 — Retrieve Data from Decommissioned Devices

<a id="capec-675"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Stable  

An adversary obtains decommissioned, recycled, or discarded systems and devices that can include an organization’s intellectual property, employee data, and other types of controlled information. Systems and devices that have reached the end of their lifecycles may be subject to recycle or disposal where they can be exposed to adversarial attempts to retrieve information from internal memory chips

## Mapped ATT&CK techniques (1)

- [T1052 — Exfiltration Over Physical Medium](/mitre/techniques/T1052.md) — Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive.

## Related CWE (1)

- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html) — The product does not properly provide a capability for the product administrator to remove sensitive data at the time the product is decommissioned.

## Prerequisites

- An adversary needs to have access to electronic data processing equipment being recycled or disposed of (e.g., laptops, servers) at a collection location and the ability to take control of it for th

## Skills required

- An adversary may need the ability to mount printed circuit boards and target individual chips for exploitation.:LEVEL:High
- An adversary

## Mitigations

- Backup device data before erasure to retain intellectual property and inside knowledge.
- Overwrite data on device rather than deleting. Deleted data can still be recovered, even if the device trash can is emptied. Rewriting data removes any trace o

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
