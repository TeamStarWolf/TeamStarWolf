# CAPEC-81 — Web Server Logs Tampering

<a id="capec-81"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

Web Logs Tampering attacks involve an attacker injecting, deleting or otherwise tampering with the contents of web logs typically for the purposes of masking other malicious behavior. Additionally, writing malicious data to log files may target jobs, filters, reports, and other agents that process the logs in an asynchronous attack pattern. This pattern of attack is similar to Log Injection-Tamper

## Related CWE (10)

[CWE-117](/CWE_REFERENCE.md) [CWE-93](/CWE_REFERENCE.md) [CWE-75](/CWE_REFERENCE.md) [CWE-221](/CWE_REFERENCE.md) [CWE-96](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-150](/CWE_REFERENCE.md) [CWE-276](/CWE_REFERENCE.md) [CWE-279](/CWE_REFERENCE.md) [CWE-116](/CWE_REFERENCE.md)

**Prerequisites:** ::Target server software must be a HTTP server that performs web logging.::

**Skills required:** ::SKILL:To input faked entries into Web logs:LEVEL:Low::

**Mitigations:** ::Design: Use input validation before writing to web log::Design: Validate all log data before it is output::


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
