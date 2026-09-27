# CAPEC-81 — Web Server Logs Tampering

<a id="capec-81"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Web Logs Tampering attacks involve an attacker injecting, deleting or otherwise tampering with the contents of web logs typically for the purposes of masking other malicious behavior. Additionally, writing malicious data to log files may target jobs, filters, reports, and other agents that process the logs in an asynchronous attack pattern. This pattern of attack is similar to Log Injection-Tamper

## Related CWE (10)

- [CWE-117 — Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CWE-93 — Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
- [CWE-75 — Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)
- [CWE-221 — Information Loss or Omission](https://cwe.mitre.org/data/definitions/221.html)
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-150 — Improper Neutralization of Escape, Meta, or Control Sequences](https://cwe.mitre.org/data/definitions/150.html)
- [CWE-276 — Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)
- [CWE-279 — Incorrect Execution-Assigned Permissions](https://cwe.mitre.org/data/definitions/279.html)
- [CWE-116 — Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

## Prerequisites

- Target server software must be a HTTP server that performs web logging.

## Skills required

- To input faked entries into Web logs:LEVEL:Low

## Mitigations

- Design: Use input validation before writing to web log
- Design: Validate all log data before it is output

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
