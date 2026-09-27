# CAPEC-28 — Fuzzing

<a id="capec-28"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** High  
**Status:** Draft  

In this attack pattern, the adversary leverages fuzzing to try to identify weaknesses in the system. Fuzzing is a software security and functionality testing method that feeds randomly constructed input to the system and looks for an indication that a failure in response to that input has occurred. Fuzzing treats the system as a black box and is totally free from any preconceptions or assumptions about the system. Fuzzing can help an attacker discover certain assumptions made about user input in the system. Fuzzing gives an attacker a quick way of potentially uncovering some of these assumptions despite not necessarily knowing anything about the internals of the system. These assumptions can then be turned against the system by specially crafting user input that may allow an attacker to achieve their goals.

## Related CWE (2)

- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html) — The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could…
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) — The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Skills required

- [Low] There is a wide variety of fuzzing tools available.

## Consequences

- Integrity / Modify Data
- Availability / Unreliable Execution
- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Alter Execution Logic

## Mitigations

- Test to ensure that the software behaves as per specification and that there are no unintended side effects. Ensure that no assumptions about the validity of data are made.
- Use fuzz testing during the software QA process to uncover any surprises, uncover any assumptions or unexpected behavior.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
