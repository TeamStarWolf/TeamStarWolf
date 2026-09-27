# CAPEC-700 — Network Boundary Bridging

<a id="capec-700"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary which has gained elevated access to network boundary devices may use these devices to create a channel to bridge trusted and untrusted networks. Boundary devices do not necessarily have to be on the network’s edge, but rather must serve to segment portions of the target network the adversary wishes to cross into.

## Mapped ATT&CK techniques (1)

- [T1599 — Network Boundary Bridging](/mitre/techniques/T1599.md)

## Prerequisites

- The adversary must have control of a network boundary device.

## Skills required

- The adversary must understand how to manage the target network device to create or edit policies which will bridge networks.:LEVEL:Medium

## Mitigations

- Design: Ensure network devices are storing credentials in encrypted stores
- Design: Follow the principle of least privilege and restrict administrative duties to as few accounts as possible. Ensure these privileged accounts are secured with strong

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
