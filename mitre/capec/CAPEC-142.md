# CAPEC-142 — DNS Cache Poisoning

<a id="capec-142"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

A domain name server translates a domain name (such as www.example.com) into an IP address that Internet hosts use to contact Internet resources. An adversary modifies a public DNS cache to cause certain names to resolve to incorrect addresses that the adversary specifies. The result is that client applications that rely upon the targeted cache for domain name resolution will be directed not to th

## Mapped ATT&CK techniques (1)

- [T1584.002 — DNS Server](/mitre/techniques/T1584-002.md) — Adversaries may compromise third-party DNS servers that can be used during targeting.

## Related CWE (5)

- [CWE-348 — Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html) — The product has two different sources of the same data or information, but it uses the source that has less support for verification, is less trusted, or is less resistant to attack.
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-349 — Acceptance of Extraneous Untrusted Data With Trusted Data](https://cwe.mitre.org/data/definitions/349.html) — The product, when processing trusted data, accepts any untrusted data that is also included with the trusted data, treating the untrusted data as if it were trusted.
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html) — The product performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision, but it does not properly ensure that the IP address is truly associated with the hostname.

## Prerequisites

- A DNS cache must be vulnerable to some attack that allows the adversary to replace addresses in its lookup table.Client applications must trust the corrupted cashed values and utilize them for their

## Skills required

- To overwrite/modify targeted DNS cache:LEVEL:Medium

## Mitigations

- Configuration: Make sure your DNS servers have been updated to the latest versions
- Configuration: UNIX services like rlogin, rsh/rcp, xhost, and nfs are all susceptible to wrong information being held in a cache. Care should be taken with these se

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
