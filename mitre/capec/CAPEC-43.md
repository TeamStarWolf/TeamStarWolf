# CAPEC-43 — Exploiting Multiple Input Interpretation Layers

<a id="capec-43"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium

An attacker supplies the target software with input data that contains sequences of special characters designed to bypass input validation logic. This exploit relies on the target making multiples passes over the input data and processing a layer of special characters with each pass. In this manner, the attacker can disguise input that would otherwise be rejected as invalid by concealing it with l

## Related CWE (10)

[CWE-179](/CWE_REFERENCE.md) [CWE-181](/CWE_REFERENCE.md) [CWE-184](/CWE_REFERENCE.md) [CWE-183](/CWE_REFERENCE.md) [CWE-77](/CWE_REFERENCE.md) [CWE-78](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md) [CWE-707](/CWE_REFERENCE.md)

**Prerequisites:** ::User input is used to construct a command to be executed on the target system or as part of the file name.::Multiple parser passes are performed on the data supplied by the user.::

**Skills required:** ::SKILL:Knowledge of various escaping schemes, such as URL escape encoding and XML escape characters.:LEVEL:Medium::

**Mitigations:** ::An iterative approach to input validation may be required to ensure that no dangerous characters are present. It may be necessary to implement redundant checking across different input validation layers. Ensure that invalid data is rejected as soon


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
