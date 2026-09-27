# CAPEC-590 — IP Address Blocking

<a id="capec-590"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Draft  

An adversary performing this type of attack drops packets destined for a target IP address. The aim is to prevent access to the service hosted at the target IP address.

## Related CWE (1)

- [CWE-300 — Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html) — The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or…

## Prerequisites

- This attack requires the ability to conduct deep packet inspection with an In-Path device that can drop the targeted traffic and/or connection.

## Mitigations

- Have a large pool of backup IPs built into the application and support proxy capability in the application.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
