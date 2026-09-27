# CAPEC-481 — Contradictory Destinations in Traffic Routing Schemes

<a id="capec-481"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Adversaries can provide contradictory destinations when sending messages. Traffic is routed in networks using the domain names in various headers available at different levels of the OSI model. In a Content Delivery Network (CDN) multiple domains might be available, and if there are contradictory domain names provided it is possible to route traffic to an inappropriate destination. The technique, called Domain Fronting, involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. An alternative technique, called Domainless Fronting, is similar, but the SNI field is left blank.

## Mapped ATT&CK techniques (1)

- [T1090.004 — Domain Fronting](/mitre/techniques/T1090-004.md) — Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through…

## Related CWE (1)

- [CWE-923 — Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html) — The product establishes a communication channel to (or from) an endpoint for privileged or protected operations, but it does not properly ensure that it is communicating with the correct endpoint.

## Prerequisites

- An adversary must be aware that their message will be routed using a CDN, and that both of the contradictory domains are served from that CDN.
- If the purpose of the Domain Fronting is to hide redirected C2 traffic, the C2 server must have been created in the CDN.

## Skills required

- [Medium] The adversary must have some knowledge of how messages are routed.

## Consequences

- Confidentiality / Read Data, Modify Data

## Mitigations

- Monitor connections, checking headers in traffic for contradictory domain names, or empty domain names.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
