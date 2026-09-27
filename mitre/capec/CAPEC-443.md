# CAPEC-443 — Malicious Logic Inserted Into Product by Authorized Developer

<a id="capec-443"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary uses their privileged position within an authorized development organization to inject malicious logic into a codebase or product.

## Mapped ATT&CK techniques (2)

- [T1195.002 — Compromise Software Supply Chain](/mitre/techniques/T1195-002.md) — Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.
- [T1195.003 — Compromise Hardware Supply Chain](/mitre/techniques/T1195-003.md) — Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- Access to the product during the initial or continuous development.

## Consequences

- Authorization / Execute Unauthorized Commands

## Mitigations

- Assess software and hardware during development and prior to deployment to ensure that it functions as intended and without any malicious functionality. This includes both initial development, as well as updates propagated to the product after deployment.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
