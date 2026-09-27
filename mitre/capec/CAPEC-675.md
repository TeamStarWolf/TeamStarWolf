# CAPEC-675 — Retrieve Data from Decommissioned Devices

<a id="capec-675"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Stable  

An adversary obtains decommissioned, recycled, or discarded systems and devices that can include an organization’s intellectual property, employee data, and other types of controlled information. Systems and devices that have reached the end of their lifecycles may be subject to recycle or disposal where they can be exposed to adversarial attempts to retrieve information from internal memory chips and storage devices that are part of the system.

## Mapped ATT&CK techniques (1)

- [T1052 — Exfiltration Over Physical Medium](/mitre/techniques/T1052.md) — Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive.

## Related CWE (1)

- [CWE-1266 — Improper Scrubbing of Sensitive Data from Decommissioned Device](https://cwe.mitre.org/data/definitions/1266.html) — The product does not properly provide a capability for the product administrator to remove sensitive data at the time the product is decommissioned.

## Prerequisites

- An adversary needs to have access to electronic data processing equipment being recycled or disposed of (e.g., laptops, servers) at a collection location and the ability to take control of it for the purpose of exploiting its content.

## Skills required

- [High] An adversary may need the ability to mount printed circuit boards and target individual chips for exploitation.
- [Medium] An adversary needs the technical skills required to extract solid state drives, hard disk drives, and other storage media to host on a compatible system or harness to gain access to digital content.

## Consequences

- Accountability / Bypass Protection Mechanism

## Mitigations

- Backup device data before erasure to retain intellectual property and inside knowledge.
- Overwrite data on device rather than deleting. Deleted data can still be recovered, even if the device trash can is emptied. Rewriting data removes any trace of the old data. Performing multiple overwrites followed by a zeroing of the device (overwriting with all zeros) is good practice.
- Use a secure erase software.
- Physically destroy the device if it is not intended to be reused. Using a specialized service to disintegrate, burn, melt or pulverize the device can be effective, but if those services are inaccessible, drilling nails or holes, or smashing the device with a hammer can be effective. Do not burn, microwave, or pour acid on a hard drive.
- Physically destroy memory and SIM cards for mobile devices not intended to be reused.
- Ensure that the user account has been terminated or switched to a new device before destroying.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
