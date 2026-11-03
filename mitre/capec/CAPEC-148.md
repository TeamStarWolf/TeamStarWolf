# CAPEC-148: Content Spoofing

<a id="capec-148"></a>

Abstraction: Meta  
Typical severity: Medium  
Likelihood: Medium  
Status: Stable  

An adversary modifies content to make it contain something other than what the original content producer intended while keeping the apparent source of the content unchanged. The term content spoofing is most often used to describe modification of web pages hosted by a target to display the adversary's content instead of the owner's content. However, any content can be spoofed, including the content of email messages, file transfers, or the content of other network communication protocols. Content can be modified at the source (e.g. modifying the source file for a web page) or in transit (e.g. intercepting and modifying a message between the sender and recipient). Usually, the adversary will attempt to hide the fact that the content has been modified, but in some cases, such as with web site defacement, this is not necessary. Content Spoofing can lead to malware exposure, financial fraud (if the content governs financial transactions), privacy violations, and other unwanted outcomes.

## Mapped ATT&CK techniques (1)

- [T1491: Defacement](/mitre/techniques/T1491.md): Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content.

## Related CWE (1)

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html): The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Prerequisites

- The target must provide content but fail to adequately protect it against modification.The adversary must have the means to alter data to which they are not authorized. If the content is to be modified in transit, the adversary must be able to intercept the targeted messages.

## Consequences

- Integrity / Modify Data

## Related pages

- [CAPEC-111: JSON Hijacking (aka JavaScript Hijacking)](/mitre/capec/CAPEC-111.md), also related to CWE-345
- [CAPEC-141: Cache Poisoning](/mitre/capec/CAPEC-141.md), also related to CWE-345
- [CAPEC-142: DNS Cache Poisoning](/mitre/capec/CAPEC-142.md), also related to CWE-345
- [CAPEC-218: Spoofing of UDDI/ebXML Messages](/mitre/capec/CAPEC-218.md), also related to CWE-345
- [CAPEC-384: Application API Message Manipulation via Man-in-the-Middle](/mitre/capec/CAPEC-384.md), also related to CWE-345
- [CAPEC-385: Transaction or Event Tampering via Application API Manipulation](/mitre/capec/CAPEC-385.md), also related to CWE-345
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
