# CAPEC-155 — Screen Temporary Files for Sensitive Information

<a id="capec-155"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Draft  

An adversary exploits the temporary, insecure storage of information by monitoring the content of files used to store temp data during an application's routine execution flow. Many applications use temporary files to accelerate processing or to provide records of state across multiple executions of the application. Sometimes, however, these temporary files may end up storing sensitive information. By screening an application's temporary files, an adversary might be able to discover such sensitive information. For example, web browsers often cache content to accelerate subsequent lookups. If the content contains sensitive information then the adversary could recover this from the web cache.

## Related CWE (1)

- [CWE-377 — Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html) — Creating and using insecure temporary files can leave application and system data vulnerable to attack.

## Prerequisites

- The target application must utilize temporary files and must fail to adequately secure them against other parties reading them.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
