# CAPEC-666 — BlueSmacking

<a id="capec-666"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An adversary uses Bluetooth flooding to transfer large packets to Bluetooth enabled devices over the L2CAP protocol with the goal of creating a DoS. This attack must be carried out within close proximity to a Bluetooth enabled device.

## Mapped ATT&CK techniques (2)

- [T1498.001 — Direct Network Flood](/mitre/techniques/T1498-001.md)
- [T1499.001 — OS Exhaustion Flood](/mitre/techniques/T1499-001.md)

## Related CWE (1)

- [CWE-404 — Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html)

## Prerequisites

- The system/application has Bluetooth enabled.

## Skills required

- An adversary only needs a Linux machine along with a Bluetooth adapter, which is extremely common.:LEVEL:Low

## Mitigations

- Disable Bluetooth when not being used.
- When using Bluetooth, set it to hidden or non-discoverable mode.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
