# CAPEC-12 — Choosing Message Identifier

<a id="capec-12"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

This pattern of attack is defined by the selection of messages distributed via multicast or public information channels that are intended for another client by determining the parameter value assigned to that client. This attack allows the adversary to gain access to potentially privileged information, and to possibly perpetrate other attacks through the distribution means by impersonation. If the

## Related CWE (2)

[CWE-201](/CWE_REFERENCE.md) [CWE-306](/CWE_REFERENCE.md)

**Prerequisites:** ::Information and client-sensitive (and client-specific) data must be present through a distribution channel available to all users.::Distribution means must code (through channel, message identifiers

**Skills required:** ::SKILL:All the adversary needs to discover is the format of the messages on the channel/distribution means and the particular identifier used within 

**Mitigations:** ::Associate some ACL (in the form of a token) with an authenticated user which they provide middleware. The middleware uses this token as part of its channel/message selection for that client, or part of a discerning authorization decision for privil


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
