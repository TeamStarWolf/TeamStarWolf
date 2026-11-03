# CAPEC-508: Shoulder Surfing

<a id="capec-508"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

In a shoulder surfing attack, an adversary observes an unaware individual's keystrokes, screen content, or conversations with the goal of obtaining sensitive information. One motive for this attack is to obtain sensitive information about the target for financial, personal, political, or other gains. From an insider threat perspective, an additional motive could be to obtain system/application credentials or cryptographic keys. Shoulder surfing attacks are accomplished by observing the content "over the victim's shoulder", as implied by the name of this attack.

## Related CWE (2)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html): The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent of the person about whom the information is collected.

## Prerequisites

- The adversary typically requires physical proximity to the target's environment, in order to observe their screen or conversation. This may not be the case if the adversary is able to record the target and obtain sensitive information upon review of the recording.

## Skills required

- [Low] In most cases, an adversary can simply observe and retain the desired information.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Be mindful of your surroundings when discussing or viewing sensitive information in public areas.
- Pertaining to insider threats, ensure that sensitive information is not displayed to nor discussed around individuals without need-to-know access to said information.

## Related pages

- [CAPEC-464: Evercookie](/mitre/capec/CAPEC-464.md), also related to CWE-359
- [CAPEC-467: Cross Site Identification](/mitre/capec/CAPEC-467.md), also related to CWE-359
- [CAPEC-498: Probe iOS Screenshots](/mitre/capec/CAPEC-498.md), also related to CWE-359
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-200
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-200
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-200
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
