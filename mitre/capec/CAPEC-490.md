# CAPEC-490 — Amplification

<a id="capec-490"></a>

**Abstraction:** Standard  
**Typical severity:**   
**Likelihood:** 

An adversary may execute an amplification where the size of a response is far greater than that of the request that generates it. The goal of this attack is to use a relatively few resources to create a large amount of traffic against a target server. To execute this attack, an adversary send a request to a 3rd party service, spoofing the source address to be that of the target server. The larger

## Mapped ATT&CK techniques (1)

- [T1498.002](/mitre/techniques/T1498-002.md)

## Related CWE (1)

[CWE-770](/CWE_REFERENCE.md)

**Prerequisites:** ::This type of an attack requires the existence of a 3rd party service that generates a response that is significantly larger than the request that triggers it.::

**Mitigations:** ::To mitigate this type of an attack, an organization can attempt to identify the 3rd party services being used in an active attack and blocking them until the attack ends. This can be accomplished by filtering traffic for suspicious message patterns


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
