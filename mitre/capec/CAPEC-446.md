# CAPEC-446 — Malicious Logic Insertion into Product via Inclusion of Third-Party Component

<a id="capec-446"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Stable  

An adversary conducts supply chain attacks by the inclusion of insecure third-party components into a technology, product, or code-base, possibly packaging a malicious driver or component along with the product before shipping it to the consumer or acquirer.

## Mapped ATT&CK techniques (1)

- [T1195 — Supply Chain Compromise](/mitre/techniques/T1195.md) — Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

## Prerequisites

- Access to the product during the initial or continuous development. This access is often obtained via insider access to include the third-party component after deployment.

## Mitigations

- Assess software and hardware during development and prior to deployment to ensure that it functions as intended and without any malicious functionality. This includes both initial development, as well as updates propagated to the product after depl

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
