# CAPEC-67 — String Format Overflow in syslog()

<a id="capec-67"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High  
**Status:** Draft  

This attack targets applications and software that uses the syslog() function insecurely. If an application does not explicitely use a format string parameter in a call to syslog(), user input can be placed in the format string parameter leading to a format string injection attack. Adversaries can then inject malicious format string commands into the function call leading to a buffer overflow. There are many reported software vulnerabilities with the root cause being a misuse of the syslog() function.

## Related CWE (6)

- [CWE-120 — Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html) — The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-134 — Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html) — The product uses a function that accepts a format string as an argument, but the format string originates from an external source.
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.
- [CWE-680 — Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html) — The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html) — The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- The Syslog function is used without specifying a format string argument, allowing user input to be placed direct into the function call as a format string.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Availability / Unreliable Execution
- Confidentiality, Access Control, Authorization / Gain Privileges
- Integrity / Modify Data

## Mitigations

- The code should be reviewed for misuse of the Syslog function call. Manual or automated code review can be used. The reviewer needs to ensure that all format string functions are passed a static string which cannot be controlled by the user and that the proper number of arguments are always sent to that function as well. If at all possible, do not use the %n operator in format strings. The following code shows a correct usage of Syslog(): syslog(LOG_ERR, "%s", cmdBuf); The following code shows a vulnerable usage of Syslog(): syslog(LOG_ERR, cmdBuf); // the buffer cmdBuff is taking user supplied data.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
