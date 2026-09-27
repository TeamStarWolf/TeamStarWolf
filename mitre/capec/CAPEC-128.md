# CAPEC-128 — Integer Attacks

<a id="capec-128"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An attacker takes advantage of the structure of integer variables to cause these variables to assume values that are not expected by an application. For example, adding one to the largest positive integer in a signed integer variable results in a negative number. Negative numbers may be illegal in an application and the application may prevent an attacker from providing them directly, but the appl

## Related CWE (1)

- [CWE-682 — Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)

## Prerequisites

- The target application must have an integer variable for which only some of the possible integer values are expected by the application and where there are no checks on the value of the variable bef

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
