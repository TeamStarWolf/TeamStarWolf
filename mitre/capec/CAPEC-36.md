# CAPEC-36 — Using Unpublished Interfaces or Functionality

<a id="capec-36"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium

An adversary searches for and invokes interfaces or functionality that the target system designers did not intend to be publicly available. If interfaces fail to authenticate requests, the attacker may be able to invoke functionality they are not authorized for.

## Related CWE (4)

[CWE-306](/CWE_REFERENCE.md) [CWE-693](/CWE_REFERENCE.md) [CWE-695](/CWE_REFERENCE.md) [CWE-1242](/CWE_REFERENCE.md)

**Prerequisites:** ::The architecture under attack must publish or otherwise make available services that clients can attach to, either in an unauthenticated fashion, or having obtained an authentication token elsewhere

**Skills required:** ::SKILL:A number of web service digging tools are available for free that help discover exposed web services and their interfaces. In the event that a

**Mitigations:** ::Authenticating both services and their discovery, and protecting that authentication mechanism simply fixes the bulk of this problem. Protecting the authentication involves the standard means, including: 1) protecting the channel over which authent


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
