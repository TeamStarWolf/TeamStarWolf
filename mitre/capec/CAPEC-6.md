# CAPEC-6 — Argument Injection

<a id="capec-6"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** High

An attacker changes the behavior or state of a targeted application through injecting data or command syntax through the targets use of non-validated and non-filtered arguments of exposed services or methods.

## Related CWE (6)

[CWE-74](/CWE_REFERENCE.md) [CWE-146](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-78](/CWE_REFERENCE.md) [CWE-185](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::Target software fails to strip all user-supplied input of any content that could cause the shell to perform unexpected actions.::Software must allow for unvalidated or unfiltered input to be execute

**Skills required:** ::SKILL:The attacker has to identify injection vector, identify the operating system-specific commands, and optionally collect the output.:LEVEL:Mediu

**Mitigations:** ::Design: Do not program input values directly on command shell, instead treat user input as guilty until proven innocent. Build a function that takes user input and converts it to applications specific types and values, stripping or filtering out al


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
