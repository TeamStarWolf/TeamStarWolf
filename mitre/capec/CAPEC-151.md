# CAPEC-151 — Identity Spoofing

<a id="capec-151"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Stable  

Identity Spoofing refers to the action of assuming (i.e., taking on) the identity of some other entity (human or non-human) and then using that identity to accomplish a goal. An adversary may craft messages that appear to come from a different principle or use stolen / spoofed authentication credentials.

## Related CWE (1)

- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

## Prerequisites

- The identity associated with the message or resource must be removable or modifiable in an undetectable way.

## Mitigations

- Employ robust authentication processes (e.g., multi-factor authentication).

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
