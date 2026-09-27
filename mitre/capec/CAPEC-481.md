# CAPEC-481 — Contradictory Destinations in Traffic Routing Schemes

<a id="capec-481"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Adversaries can provide contradictory destinations when sending messages. Traffic is routed in networks using the domain names in various headers available at different levels of the OSI model. In a Content Delivery Network (CDN) multiple domains might be available, and if there are contradictory domain names provided it is possible to route traffic to an inappropriate destination. The technique,

## Mapped ATT&CK techniques (1)

- [T1090.004 — Domain Fronting](/mitre/techniques/T1090-004.md)

## Related CWE (1)

- [CWE-923 — Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html)

## Prerequisites

- An adversary must be aware that their message will be routed using a CDN, and that both of the contradictory domains are served from that CDN.
- If the purpose of the Domain Fronting is to hide redir

## Skills required

- The adversary must have some knowledge of how messages are routed.:LEVEL:Medium

## Mitigations

- Monitor connections, checking headers in traffic for contradictory domain names, or empty domain names.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
