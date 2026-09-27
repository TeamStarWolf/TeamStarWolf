# CAPEC-148 — Content Spoofing

<a id="capec-148"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Medium  
**Status:** Stable  

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary's content instead of the owner's content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

## Mapped ATT&CK techniques (1)

- [T1491 — Defacement](/mitre/techniques/T1491.md) — Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content.

## Related CWE (1)

- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Prerequisites

- The target must provide content but fail to adequately protect it against modification.The adversary must have the means to alter data to which they are not authorized. If the content is to be modified in transit, the adversary must be able to intercept the targeted messages.

## Consequences

- Integrity / Modify Data

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
