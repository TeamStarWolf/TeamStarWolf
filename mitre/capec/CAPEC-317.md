# CAPEC-317 — IP ID Sequencing Probe

<a id="capec-317"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** Medium  
**Status:** Stable  

This OS fingerprinting probe analyzes the IP 'ID' field sequence number generation algorithm of a remote host. Operating systems generate IP 'ID' numbers differently, allowing an attacker to identify the operating system of the host by examining how is assigns ID numbers when generating response packets. RFC 791 does not specify how ID numbers are chosen or their ranges, so ID sequence generation

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
