# CAPEC-117 — Interception

<a id="capec-117"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Stable  

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream or passively observe the communications as they unfold. In all variants of this attack, the adversary is not the intended recipient of the data stream. In contrast to other means of gathering information (e.g., targeting data leaks), the adversary must actively position themself so as to observe explicit data channels (e.g. network traffic) and read the content. However, this attack differs from a Adversary-In-the-Middle (CAPEC-94) attack, as the adversary does not alter the content of the communications nor forward data to the intended recipient.

## Related CWE (1)

- [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html) — The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.

## Prerequisites

- The target must transmit data over a medium that is accessible to the adversary.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
