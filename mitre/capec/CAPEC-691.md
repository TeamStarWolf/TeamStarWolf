# CAPEC-691 — Spoof Open-Source Software Metadata

<a id="capec-691"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary spoofs open-source software metadata in an attempt to masquerade malicious software as popular, maintained, and trusted.

## Mapped ATT&CK techniques (2)

- [T1195.001 — Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md) — Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise.
- [T1195.002 — Compromise Software Supply Chain](/mitre/techniques/T1195-002.md) — Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

## Related CWE (1)

- [CWE-494 — Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html) — The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Prerequisites

- Identification of a popular open-source component whose metadata is to be spoofed.

## Skills required

- [Medium] Ability to spoof a variety of software metadata to convince victims the source is trusted.

## Consequences

- Integrity / Modify Data
- Accountability / Hide Activities
- Access Control, Authorization / Execute Unauthorized Commands, Alter Execution Logic, Gain Privileges

## Mitigations

- Before downloading open-source software, perform precursory metadata checks to determine the author(s), frequency of updates, when the software was last updated, and if the software is widely leveraged.
- Within package managers, look for conflicting or non-unique repository references to determine if multiple packages share the same repository reference.
- Reference vulnerability databases to determine if the software contains known vulnerabilities.
- Only download open-source software from reputable hosting sites or package managers.
- Only download open-source software that has been adequately signed by the developer(s). For repository commits/tags, look for the "Verified" status and for developers leveraging "Vigilant Mode" (GitHub) or similar modes.
- After downloading open-source software, ensure integrity values have not changed.
- Before executing or incorporating the software, leverage automated testing techniques (e.g., static and dynamic analysis) to determine if the software behaves maliciously.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
