# CAPEC-15 — Command Delimiters

<a id="capec-15"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An attack of this type exploits a programs' vulnerabilities that allows an attacker's commands to be concatenated onto a legitimate command with the intent of targeting other resources such as the file system or database. The system that uses a filter or denylist input validation, as opposed to allowlist validation is vulnerable to an attacker who predicts delimiters (or combinations of delimiters

## Related CWE (11)

[CWE-146](/CWE_REFERENCE.md) [CWE-77](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-78](/CWE_REFERENCE.md) [CWE-185](/CWE_REFERENCE.md) [CWE-93](/CWE_REFERENCE.md) [CWE-140](/CWE_REFERENCE.md) [CWE-157](/CWE_REFERENCE.md) [CWE-138](/CWE_REFERENCE.md) [CWE-154](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::Software's input validation or filtering must not detect and block presence of additional malicious command.::

**Skills required:** ::SKILL:The attacker has to identify injection vector, identify the specific commands, and optionally collect the output, i.e. from an interactive ses

**Mitigations:** ::Design: Perform allowlist validation against a positive specification for command length, type, and parameters.::Design: Limit program privileges, so if commands circumvent program input validation or filter routines then commands do not running un


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
