# CAPEC-194 — Fake the Source of Data

<a id="capec-194"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Stable  

An adversary takes advantage of improper authentication to provide data or services under a falsified identity. The purpose of using the falsified identity may be to prevent traceability of the provided data or to assume the rights granted to another individual. One of the simplest forms of this attack would be the creation of an email message with a modified From field in order to appear that the

## Related CWE (1)

- [CWE-287 — Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

## Prerequisites

- This attack is only applicable when a vulnerable entity associates data or services with an identity. Without such an association, there would be no reason to fake the source.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
