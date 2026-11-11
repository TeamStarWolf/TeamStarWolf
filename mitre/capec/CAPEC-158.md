# CAPEC-158: Sniffing Network Traffic

<a id="capec-158"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

In this attack pattern, the adversary monitors network traffic between nodes of a public or multicast network in an attempt to capture sensitive information at the protocol level. Network sniffing applications can reveal TCP/IP, DNS, Ethernet, and other low-level network communication information. The adversary takes a passive role in this attack pattern and simply observes and analyzes the traffic. The adversary may precipitate or indirectly influence the content of the observed transaction, but is never the intended recipient of the target information.

## Mapped ATT&CK techniques (2)

- [T1040: Network Sniffing](/mitre/techniques/T1040.md): Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.
- [T1111: Multi-Factor Authentication Interception](/mitre/techniques/T1111.md): Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources.

## Related CWE (1)

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html): The product does not encrypt sensitive or critical information before storage or transmission.

## Prerequisites

- The target must be communicating on a network protocol visible by a network sniffing application.
- The adversary must obtain a logical position on the network from intercepting target network traffic is possible. Depending on the network topology, traffic sniffing may be simple or challenging. If both the target sender and target recipient are members of a single subnet, the adversary must also be on that subnet in order to see their traffic communication.

## Skills required

- [Low] Adversaries can obtain and set up open-source network sniffing tools easily.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Obfuscate network traffic through encryption to prevent its readability by network sniffers.
- Employ appropriate levels of segmentation to your network in accordance with best practices.

## Related pages

- [CAPEC-31: Accessing/Intercepting/Modifying HTTP Cookies](/mitre/capec/CAPEC-31.md), also related to CWE-311
- [CAPEC-37: Retrieve Embedded Sensitive Data](/mitre/capec/CAPEC-37.md), also related to CWE-311
- [CAPEC-65: Sniff Application Code](/mitre/capec/CAPEC-65.md), also related to CWE-311
- [CAPEC-157: Sniffing Attacks](/mitre/capec/CAPEC-157.md), also related to CWE-311
- [CAPEC-204: Lifting Sensitive Data Embedded in Cache](/mitre/capec/CAPEC-204.md), also related to CWE-311
- [CAPEC-383: Harvesting Information via API Event Monitoring](/mitre/capec/CAPEC-383.md), also related to CWE-311
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
