# CAPEC-15: Command Delimiters

<a id="capec-15"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attack of this type exploits a programs' vulnerabilities that allows an attacker's commands to be concatenated onto a legitimate command with the intent of targeting other resources such as the file system or database. The system that uses a filter or denylist input validation, as opposed to allowlist validation is vulnerable to an attacker who predicts delimiters (or combinations of delimiters) not present in the filter or denylist. As with other injection attacks, the attacker uses the command delimiter payload as an entry point to tunnel through the application and activate additional attacks through SQL queries, shell commands, network scanning, and so on.

## Related CWE (11)

- [CWE-146: Improper Neutralization of Expression/Command Delimiters](https://cwe.mitre.org/data/definitions/146.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as expression or command delimiters when they are sent to a downstream component.
- [CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html): The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.
- [CWE-184: Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html): The product implements a protection mechanism that relies on a list of inputs (or properties of inputs) that are not allowed by policy or otherwise require other action to neutralize before additional processing takes place, but the list is incomplete.
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html): The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.
- [CWE-185: Incorrect Regular Expression](https://cwe.mitre.org/data/definitions/185.html): The product specifies a regular expression in a way that causes data to be improperly matched or compared.
- [CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html): The product uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.
- [CWE-140: Improper Neutralization of Delimiters](https://cwe.mitre.org/data/definitions/140.html): The product does not neutralize or incorrectly neutralizes delimiters.
- [CWE-157: Failure to Sanitize Paired Delimiters](https://cwe.mitre.org/data/definitions/157.html): The product does not properly handle the characters that are used to mark the beginning and ending of a group of entities, such as parentheses, brackets, and braces.
- [CWE-138: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as control elements or syntactic markers when they are sent to a downstream component.
- [CWE-154: Improper Neutralization of Variable Name Delimiters](https://cwe.mitre.org/data/definitions/154.html): The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could be interpreted as variable name delimiters when they are sent to a downstream component.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- Software's input validation or filtering must not detect and block presence of additional malicious command.

## Skills required

- [Medium] The attacker has to identify injection vector, identify the specific commands, and optionally collect the output, i.e. from an interactive session.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality / Read Data

## Mitigations

- Design: Perform allowlist validation against a positive specification for command length, type, and parameters.
- Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running under a privileged account
- Implementation: Perform input validation for all remote content.
- Implementation: Use type conversions such as JDBC prepared statements.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
