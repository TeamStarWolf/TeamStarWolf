# CAPEC-554 — Functionality Bypass

<a id="capec-554"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary attacks a system by bypassing some or all functionality intended to protect it. Often, a system user will think that protection is in place, but the functionality behind those protections has been disabled by the adversary.

## Related CWE (2)

- [CWE-424 — Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html) — The product does not sufficiently protect all possible paths that a user can take to access restricted functionality or resources.
- [CWE-1299 — Missing Protection Mechanism for Alternate Hardware Interface](https://cwe.mitre.org/data/definitions/1299.html) — The lack of protections on alternate paths to access control-protected assets (such as unprotected shadow registers and other external facing unguarded interfaces) allows an attacker to bypass existing protections to the asset that are only performed against the primary path.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
