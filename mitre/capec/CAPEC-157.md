# CAPEC-157: Sniffing Attacks

<a id="capec-157"></a>

Abstraction: Standard  
Typical severity: Medium  
Status: Draft  

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient. Sniffing Attacks are similar to Adversary-In-The-Middle attacks (CAPEC-94), but are entirely passive. AiTM attacks are predominantly active and often alter the content of the communications themselves.

## Related CWE (1)

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- The target data stream must be transmitted on a medium to which the adversary has access.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

## Related pages

- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), named in the description above
- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](/mitre/capec/CAPEC-31.md), also related to CWE-311
- [CAPEC-37: Retrieve Embedded Sensitive Data](/mitre/capec/CAPEC-37.md), also related to CWE-311
- [CAPEC-65: Sniff Application Code](/mitre/capec/CAPEC-65.md), also related to CWE-311
- [CAPEC-158: Sniffing Network Traffic](/mitre/capec/CAPEC-158.md), also related to CWE-311
- [CAPEC-204: Lifting Sensitive Data Embedded in Cache](/mitre/capec/CAPEC-204.md), also related to CWE-311
- [CAPEC-383: Harvesting Information via API Event Monitoring](/mitre/capec/CAPEC-383.md), also related to CWE-311
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
