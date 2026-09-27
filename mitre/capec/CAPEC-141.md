# CAPEC-141 — Cache Poisoning

<a id="capec-141"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attacker exploits the functionality of cache technologies to cause specific data to be cached that aids the attackers' objectives. This describes any attack whereby an attacker places incorrect or harmful material in cache. The targeted cache can be an application's cache (e.g. a web browser cache) or a public cache (e.g. a DNS or ARP cache). Until the cache is refreshed, most applications or c

## Mapped ATT&CK techniques (1)

- [T1557.002 — ARP Cache Poisoning](/mitre/techniques/T1557-002.md)

## Related CWE (4)

- [CWE-348 — Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html)
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-349 — Acceptance of Extraneous Untrusted Data With Trusted Data](https://cwe.mitre.org/data/definitions/349.html)
- [CWE-346 — Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

## Prerequisites

- The attacker must be able to modify the value stored in a cache to match a desired value.
- The targeted application must not be able to detect the illicit modification of the cache and must trust th

## Skills required

- To overwrite/modify targeted cache:LEVEL:Medium

## Mitigations

- Configuration: Disable client side caching.
- Implementation: Listens for query replies on a network, and sends a notification via email when an entry changes.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
