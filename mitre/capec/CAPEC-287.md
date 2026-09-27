# CAPEC-287 — TCP SYN Scan

<a id="capec-287"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Stable  

An adversary uses a SYN scan to determine the status of ports on the remote target. SYN scanning is the most common type of port scanning that is used because of its many advantages and few drawbacks. As a result, novice attackers tend to overly rely on the SYN scan while performing system reconnaissance. As a scanning method, the primary advantages of SYN scanning are its universality and speed.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Prerequisites

- This scan type is not possible with some operating systems (Windows XP SP 2). On Linux and Unix systems it requires root privileges to use raw sockets.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
