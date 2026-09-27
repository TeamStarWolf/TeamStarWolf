# CAPEC-275 — DNS Rebinding

<a id="capec-275"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

An adversary serves content whose IP address is resolved by a DNS server that the adversary controls. After initial contact by a web browser (or similar client), the adversary changes the IP address to which its name resolves, to an address within the target organization that is not publicly accessible. This allows the web browser to examine this internal address on behalf of the adversary.

## Related CWE (1)

- [CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

## Prerequisites

- The target browser must access content server from the adversary controlled DNS name. Web advertisements are often used for this purpose. The target browser must honor the TTL value returned by the

## Skills required

- Setup DNS server and the adversary's web server. Write a malicious script to allow the victim to connect to the web server.:LEVEL:Medium

## Mitigations

- Design: IP Pinning causes browsers to record the IP address to which a given name resolves and continue using this address regardless of the TTL set in the DNS response. Unfortunately, this is incompatible with the design of some legitimate sites.:

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
