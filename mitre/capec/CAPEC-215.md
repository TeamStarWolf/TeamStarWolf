# CAPEC-215 — Fuzzing for application mapping

<a id="capec-215"></a>

**Abstraction:** Detailed  
**Typical severity:** Low  
**Likelihood:** High

An attacker sends random, malformed, or otherwise unexpected messages to a target application and observes the application's log or error messages returned. The attacker does not initially know how a target will respond to individual messages but by attempting a large number of message variants they may find a variant that trigger's desired behavior. In this attack, the purpose of the fuzzing is t

## Related CWE (2)

[CWE-209](/CWE_REFERENCE.md) [CWE-532](/CWE_REFERENCE.md)

**Prerequisites:** ::The target application must fail to sanitize incoming messages adequately before processing.::

**Skills required:** ::SKILL:Although fuzzing parameters is not difficult, and often possible with automated fuzzing tools, interpreting the error conditions and modifying

**Mitigations:** ::Design: Construct a 'code book' for error messages. When using a code book, application error messages aren't generated in string or stack trace form, but are catalogued and replaced with a unique (often integer-based) value 'coding' for the error.


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
