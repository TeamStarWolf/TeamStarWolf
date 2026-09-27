# CAPEC-144 — Detect Unpublicized Web Services

<a id="capec-144"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

An adversary searches a targeted web site for web services that have not been publicized. This attack can be especially dangerous since unpublished but available services may not have adequate security controls placed upon them given that an administrator may believe they are unreachable.

## Related CWE (1)

- [CWE-425 — Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html) — The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.

## Prerequisites

- The targeted web site must include unpublished services within its web tree. The nature of these services determines the severity of this attack.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
