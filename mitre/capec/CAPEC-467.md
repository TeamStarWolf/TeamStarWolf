# CAPEC-467: Cross Site Identification

<a id="capec-467"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An attacker harvests identifying information about a victim via an active session that the victim's browser has with a social networking site. A victim may have the social networking site open in one tab or perhaps is simply using the "remember me" feature to keep their session with the social networking site active. An attacker induces a payload to execute in the victim's browser that transparently to the victim initiates a request to the social networking site (e.g., via available social network site APIs) to retrieve identifying information about a victim. While some of this information may be public, the attacker is able to harvest this information in context and may use it for further attacks on the user (e.g., spear phishing).

## Related CWE (2)

- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html): The web application does not, or cannot, sufficiently verify whether a request was intentionally provided by the user who sent the request, which could have originated from an unauthorized actor.
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html): The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent of the person about whom the information is collected.

## Prerequisites

- The victim has an active session with the social networking site.

## Skills required

- [High] An attacker should be able to create a payload and deliver it to the victim's browser.
- [Medium] An attacker needs to know how to interact with various social networking sites (e.g., via available APIs) to request information and how to send the harvested data back to the attacker.

## Mitigations

- Usage: Users should always explicitly log out from the social networking sites when done using them.
- Usage: Users should not open other tabs in the browser when using a social networking site.

## Related pages

- [CAPEC-62: Cross Site Request Forgery](/mitre/capec/CAPEC-62.md), also related to CWE-352
- [CAPEC-111: JSON Hijacking (aka JavaScript Hijacking)](/mitre/capec/CAPEC-111.md), also related to CWE-352
- [CAPEC-462: Cross-Domain Search Timing](/mitre/capec/CAPEC-462.md), also related to CWE-352
- [CAPEC-464: Evercookie](/mitre/capec/CAPEC-464.md), also related to CWE-359
- [CAPEC-498: Probe iOS Screenshots](/mitre/capec/CAPEC-498.md), also related to CWE-359
- [CAPEC-508: Shoulder Surfing](/mitre/capec/CAPEC-508.md), also related to CWE-359
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
