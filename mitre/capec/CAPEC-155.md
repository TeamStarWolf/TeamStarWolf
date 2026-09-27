# CAPEC-155 — Screen Temporary Files for Sensitive Information

<a id="capec-155"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Likelihood:** Medium

An adversary exploits the temporary, insecure storage of information by monitoring the content of files used to store temp data during an application's routine execution flow. Many applications use temporary files to accelerate processing or to provide records of state across multiple executions of the application. Sometimes, however, these temporary files may end up storing sensitive information.

## Related CWE (1)

[CWE-377](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must utilize temporary files and must fail to adequately secure them against other parties reading them.::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
