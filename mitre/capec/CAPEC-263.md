# CAPEC-263 — Force Use of Corrupted Files

<a id="capec-263"></a>

**Abstraction:** Detailed  
**Typical severity:** Medium  
**Status:** Draft  

This describes an attack where an application is forced to use a file that an attacker has corrupted. The result is often a denial of service caused by the application being unable to process the corrupted file, but other results, including the disabling of filters or access controls (if the application fails in an unsafe way rather than failing by locking down) or buffer overflows are possible.

## Related CWE (1)

- [CWE-829 — Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) — The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

## Prerequisites

- The targeted application must utilize a configuration file that an attacker is able to corrupt. In some cases, the attacker must be able to force the (re-)reading of the corrupted file if the file i

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
