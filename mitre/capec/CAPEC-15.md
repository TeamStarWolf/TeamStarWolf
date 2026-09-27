# CAPEC-15 — Command Delimiters

<a id="capec-15"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An attack of this type exploits a programs' vulnerabilities that allows an attacker's commands to be concatenated onto a legitimate command with the intent of targeting other resources such as the file system or database. The system that uses a filter or denylist input validation, as opposed to allowlist validation is vulnerable to an attacker who predicts delimiters (or combinations of delimiters

## Related CWE (11)

- [CWE-146 — Improper Neutralization of Expression/Command Delimiters](https://cwe.mitre.org/data/definitions/146.html)
- [CWE-77 — Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-78 — Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-185 — Incorrect Regular Expression](https://cwe.mitre.org/data/definitions/185.html)
- [CWE-93 — Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)
- [CWE-140 — Improper Neutralization of Delimiters](https://cwe.mitre.org/data/definitions/140.html)
- [CWE-157 — Failure to Sanitize Paired Delimiters](https://cwe.mitre.org/data/definitions/157.html)
- [CWE-138 — Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)
- [CWE-154 — Improper Neutralization of Variable Name Delimiters](https://cwe.mitre.org/data/definitions/154.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)

## Prerequisites

- Software's input validation or filtering must not detect and block presence of additional malicious command.

## Skills required

- The attacker has to identify injection vector, identify the specific commands, and optionally collect the output, i.e. from an interactive ses

## Mitigations

- Design: Perform allowlist validation against a positive specification for command length, type, and parameters.
- Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running un

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
