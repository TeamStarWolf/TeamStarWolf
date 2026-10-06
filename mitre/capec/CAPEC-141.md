# CAPEC-141: Cache Poisoning

<a id="capec-141"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attacker exploits the functionality of cache technologies to cause specific data to be cached that aids the attackers' objectives. This describes any attack whereby an attacker places incorrect or harmful material in cache. The targeted cache can be an application's cache (e.g. a web browser cache) or a public cache (e.g. a DNS or ARP cache). Until the cache is refreshed, most applications or clients will treat the corrupted cache value as valid. This can lead to a wide range of exploits including redirecting web browsers towards sites that install malware and repeatedly incorrect calculations based on the incorrect value.

## Mapped ATT&CK techniques (1)

- [T1557.002: ARP Cache Poisoning](/mitre/techniques/T1557-002.md): Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices.

## Related CWE (4)

- [CWE-348: Use of Less Trusted Source](https://cwe.mitre.org/data/definitions/348.html): The product has two different sources of the same data or information, but it uses the source that has less support for verification, is less trusted, or is less resistant to attack.
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html): The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data](https://cwe.mitre.org/data/definitions/349.html): The product, when processing trusted data, accepts any untrusted data that is also included with the trusted data, treating the untrusted data as if it were trusted.
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html): The product does not properly verify that the source of data or communication is valid.

## Prerequisites

- The attacker must be able to modify the value stored in a cache to match a desired value.
- The targeted application must not be able to detect the illicit modification of the cache and must trust the cache value in its calculations.

## Skills required

- [Medium] To overwrite/modify targeted cache

## Mitigations

- Configuration: Disable client side caching.
- Implementation: Listens for query replies on a network, and sends a notification via email when an entry changes.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
