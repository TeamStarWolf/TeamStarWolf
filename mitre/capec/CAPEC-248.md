# CAPEC-248 — Command Injection

<a id="capec-248"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium

An adversary looking to execute a command of their choosing, injects new items into an existing command thus modifying interpretation away from what was intended. Commands in this context are often standalone strings that are interpreted by a downstream component and cause specific responses. This type of attack is possible when untrusted values are used to build these command strings. Weaknesses

## Related CWE (1)

[CWE-77](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must accept input from the user and then use this input in the construction of commands to be executed. In virtually all cases, this is some form of string input that is conca

**Mitigations:** ::All user-controllable input should be validated and filtered for potentially unwanted characters. Using an allowlist for input is desired, but if use of a denylist approach is necessary, then focusing on command related terms and delimiters is nece


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
