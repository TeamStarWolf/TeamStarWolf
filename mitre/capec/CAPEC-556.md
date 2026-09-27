# CAPEC-556 — Replace File Extension Handlers

<a id="capec-556"></a>

**Abstraction:** Detailed  
**Status:** Draft  

When a file is opened, its file handler is checked to determine which program opens the file. File handlers are configuration properties of many operating systems. Applications can modify the file handler for a given file extension to call an arbitrary program when a file with the given extension is opened.

## Mapped ATT&CK techniques (1)

- [T1546.001 — Change Default File Association](/mitre/techniques/T1546-001.md) — Adversaries may establish persistence by executing malicious content triggered by a file type association.

## Related CWE (1)

- [CWE-284 — Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) — The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Inspect registry for changes. Limit privileges of user accounts so changes to default file handlers can only be performed by authorized administrators.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
