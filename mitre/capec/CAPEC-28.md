# CAPEC-28 — Fuzzing

<a id="capec-28"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** High

In this attack pattern, the adversary leverages fuzzing to try to identify weaknesses in the system. Fuzzing is a software security and functionality testing method that feeds randomly constructed input to the system and looks for an indication that a failure in response to that input has occurred. Fuzzing treats the system as a black box and is totally free from any preconceptions or assumptions

## Related CWE (2)

[CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Skills required:** ::SKILL:There is a wide variety of fuzzing tools available.:LEVEL:Low::

**Mitigations:** ::Test to ensure that the software behaves as per specification and that there are no unintended side effects. Ensure that no assumptions about the validity of data are made.::Use fuzz testing during the software QA process to uncover any surprises, 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
