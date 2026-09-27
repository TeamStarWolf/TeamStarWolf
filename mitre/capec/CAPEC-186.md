# CAPEC-186 — Malicious Software Update

<a id="capec-186"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Status:** Draft  

An adversary uses deceptive methods to cause a user or an automated process to download and install dangerous code believed to be a valid update that originates from an adversary controlled source.

## Mapped ATT&CK techniques (1)

- [T1195.002 — Compromise Software Supply Chain](/mitre/techniques/T1195-002.md) — Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

## Related CWE (1)

- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) — The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Skills required

- [High] This attack requires advanced cyber capabilities

## Consequences

- Access Control, Availability, Confidentiality / Execute Unauthorized Commands

## Mitigations

- Validate software updates before installing.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
