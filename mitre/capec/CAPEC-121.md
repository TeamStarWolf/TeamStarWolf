# CAPEC-121 — Exploit Non-Production Interfaces

<a id="capec-121"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Low  
**Status:** Stable  

An adversary exploits a sample, demonstration, test, or debug interface that is unintentionally enabled on a production system, with the goal of gleaning information or leveraging functionality that would otherwise be unavailable.

## Related CWE (10)

- [CWE-489 — Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [CWE-1209 — Failure to Disable Reserved Bits](https://cwe.mitre.org/data/definitions/1209.html)
- [CWE-1259 — Improper Restriction of Security Token Assignment](https://cwe.mitre.org/data/definitions/1259.html)
- [CWE-1267 — Policy Uses Obsolete Encoding](https://cwe.mitre.org/data/definitions/1267.html)
- [CWE-1270 — Generation of Incorrect Security Tokens](https://cwe.mitre.org/data/definitions/1270.html)
- [CWE-1294 — Insecure Security Identifier Mechanism](https://cwe.mitre.org/data/definitions/1294.html)
- [CWE-1295 — Debug Messages Revealing Unnecessary Information](https://cwe.mitre.org/data/definitions/1295.html)
- [CWE-1296 — Incorrect Chaining or Granularity of Debug Components](https://cwe.mitre.org/data/definitions/1296.html)
- [CWE-1302 — Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC)](https://cwe.mitre.org/data/definitions/1302.html)
- [CWE-1313 — Hardware Allows Activation of Test or Debug Logic at Runtime](https://cwe.mitre.org/data/definitions/1313.html)

## Prerequisites

- The target must have configured non-production interfaces and failed to secure or remove them when brought into a production environment.

## Skills required

- Exploiting non-production interfaces requires significant skill and knowledge about the potential non-production interfaces left enabled in pr

## Mitigations

- Ensure that production systems do not contain non-production interfaces and that these interfaces are only used in development environments.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
