# CAPEC-89 — Pharming

<a id="capec-89"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

A pharming attack occurs when the victim is fooled into entering sensitive data into supposedly trusted locations, such as an online bank site or a trading platform. An attacker can impersonate these supposedly trusted sites and have the victim be directed to their site rather than the originally intended one. Pharming does not require script injection or clicking on malicious links for the attack

## Related CWE (2)

- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html) — The product does not properly verify that the source of data or communication is valid.
- [CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html) — The product performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision, but it does not properly ensure that the IP address is truly associated with the hostname.

## Prerequisites

- Vulnerable DNS software or improperly protected hosts file or router that can be poisoned
- A website that handles sensitive information but does not use a secure connection and a certificate that is

## Skills required

- The attacker needs to be able to poison the resolver - DNS entries or local hosts file or router entry pointing to a trusted DNS server - in o

## Mitigations

- All sensitive information must be handled over a secure connection.
- Known vulnerabilities in DNS or router software or in operating systems must be patched as soon as a fix has been released and tested.
- End users must ensure that they provide sen

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
