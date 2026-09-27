# CAPEC-143 — Detect Unpublicized Web Pages

<a id="capec-143"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Status:** Draft  

An adversary searches a targeted web site for web pages that have not been publicized. In doing this, the adversary may be able to gain access to information that the targeted site did not intend to make public.

## Related CWE (1)

- [CWE-425 — Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html) — The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.

## Prerequisites

- The targeted web site must include pages within its published tree that are not connected to its tree of links. The sensitivity of the content of these pages determines the severity of this attack.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
