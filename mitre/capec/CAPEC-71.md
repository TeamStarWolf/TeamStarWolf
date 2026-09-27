# CAPEC-71 — Using Unicode Encoding to Bypass Validation Logic

<a id="capec-71"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An attacker may provide a Unicode string to a system component that is not Unicode aware and use that to circumvent the filter or cause the classifying mechanism to fail to properly understanding the request. That may allow the attacker to slip malicious data past the content filter and/or possibly cause the application to route the request incorrectly.

## Related CWE (11)

- [CWE-176 — Improper Handling of Unicode Encoding](https://cwe.mitre.org/data/definitions/176.html)
- [CWE-179 — Incorrect Behavior Order: Early Validation](https://cwe.mitre.org/data/definitions/179.html)
- [CWE-180 — Incorrect Behavior Order: Validate Before Canonicalize](https://cwe.mitre.org/data/definitions/180.html)
- [CWE-173 — Improper Handling of Alternate Encoding](https://cwe.mitre.org/data/definitions/173.html)
- [CWE-172 — Encoding Error](https://cwe.mitre.org/data/definitions/172.html)
- [CWE-184 — Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)
- [CWE-183 — Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
- [CWE-74 — Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-697 — Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html)
- [CWE-692 — Incomplete Denylist to Cross-Site Scripting](https://cwe.mitre.org/data/definitions/692.html)

## Prerequisites

- Filtering is performed on data that has not be properly canonicalized.

## Skills required

- An attacker needs to understand Unicode encodings and have an idea (or be able to find out) what system components may not be Unicode aware.:L

## Mitigations

- Ensure that the system is Unicode aware and can properly process Unicode data. Do not make an assumption that data will be in ASCII.
- Ensure that filtering or input validation is applied to canonical data.
- Assume all input is malicious. Create an

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
