# CAPEC-81 — Web Server Logs Tampering

<a id="capec-81"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

Web Logs Tampering attacks involve an attacker injecting, deleting or otherwise tampering with the contents of web logs typically for the purposes of masking other malicious behavior. Additionally, writing malicious data to log files may target jobs, filters, reports, and other agents that process the logs in an asynchronous attack pattern. This pattern of attack is similar to "Log Injection-Tampering-Forging" except that in this case, the attack is targeting the logs of the web server and not the application.

## Related CWE (10)

- [CWE-117 — Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html) — The product constructs a log message from external input, but it does not neutralize or incorrectly neutralizes special elements when the message is written to a log file.
- [CWE-93 — Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html) — The product uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.
- [CWE-75 — Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html) — The product does not adequately filter user-controlled input for special elements with control implications.
- [CWE-221 — Information Loss or Omission](https://cwe.mitre.org/data/definitions/221.html) — The product does not record, or improperly records, security-relevant information that leads to an incorrect decision or hampers later analysis.
- [CWE-96 — Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-150 — Improper Neutralization of Escape, Meta, or Control Sequences](https://cwe.mitre.org/data/definitions/150.html) — The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as escape, meta, or control character sequences when they are sent…
- [CWE-276 — Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html) — During installation, installed file permissions are set to allow anyone to modify those files.
- [CWE-279 — Incorrect Execution-Assigned Permissions](https://cwe.mitre.org/data/definitions/279.html) — While it is executing, the product sets the permissions of an object in a way that violates the intended permissions that have been specified by the user.
- [CWE-116 — Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html) — The product prepares a structured message for communication with another component, but encoding or escaping of the data is either missing or done incorrectly.

## Prerequisites

- Target server software must be a HTTP server that performs web logging.

## Skills required

- [Low] To input faked entries into Web logs

## Consequences

- Integrity / Modify Data

## Mitigations

- Design: Use input validation before writing to web log
- Design: Validate all log data before it is output

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
