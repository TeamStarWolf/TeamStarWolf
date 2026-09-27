# CAPEC-127 — Directory Indexing

<a id="capec-127"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

An adversary crafts a request to a target that results in the target listing/indexing the content of a directory as output. One common method of triggering directory contents as output is to construct a request containing a path that terminates in a directory name rather than a file name since many applications are configured to provide a list of the directory's contents when such a request is rec

## Mapped ATT&CK techniques (1)

- [T1083 — File and Directory Discovery](/mitre/techniques/T1083.md)

## Related CWE (7)

- [CWE-424 — Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)
- [CWE-425 — Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
- [CWE-288 — Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)
- [CWE-285 — Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-276 — Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

## Prerequisites

- The target must be misconfigured to return a list of a directory's content when it receives a request that ends in a directory name rather than a file name.
- The adversary must be able to control th

## Skills required

- To issue the request to URL without given a specific file name:LEVEL:Low
- To bypass the access control of the directory of listings:LEVE

## Mitigations

- 1. Using blank index.html: putting blank index.html simply prevent directory listings from displaying to site visitors.
- 2. Preventing with .htaccess in Apache web server: In .htaccess, write Options-indexes.
- 3. Suppressing error messages: using e

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
