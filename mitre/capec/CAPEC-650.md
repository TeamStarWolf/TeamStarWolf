# CAPEC-650 — Upload a Web Shell to a Web Server

<a id="capec-650"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** 

By exploiting insufficient permissions, it is possible to upload a web shell to a web server in such a way that it can be executed remotely. This shell can have various capabilities, thereby acting as a gateway to the underlying web server. The shell might execute at the higher permission level of the web server, providing the ability the execute malicious code at elevated levels.

## Mapped ATT&CK techniques (1)

- [T1505.003](/mitre/techniques/T1505-003.md)

## Related CWE (2)

[CWE-287](/CWE_REFERENCE.md) [CWE-553](/CWE_REFERENCE.md)

**Prerequisites:** ::The web server is susceptible to one of the various web application exploits that allows for uploading a shell file.::

**Mitigations:** ::Make sure your web server is up-to-date with all patches to protect against known vulnerabilities.::Ensure that the file permissions in directories on the web server from which files can be execute is set to the least privilege settings, and that t


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
