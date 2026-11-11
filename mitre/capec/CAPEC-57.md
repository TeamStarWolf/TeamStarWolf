# CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data

<a id="capec-57"></a>

Abstraction: Detailed  
Typical severity: Very High  
Likelihood: Medium  
Status: Draft  

This attack utilizes a REST(REpresentational State Transfer)-style applications' trust in the system resources and environment to obtain sensitive data once SSL is terminated.

## Mapped ATT&CK techniques (1)

- [T1040: Network Sniffing](/mitre/techniques/T1040.md): Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.

## Related CWE (3)

- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html): The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html): When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- Opportunity to intercept must exist beyond the point where SSL is terminated.
- The adversary must be able to insert a listener actively (proxying the communication) or passively (sniffing the communication) in the client-server communication path.

## Skills required

- [Low] To insert a network sniffer or other listener into the communication stream

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Implementation: Implement message level security such as HMAC in the HTTP communication
- Design: Utilize defense in depth, do not rely on a single security mechanism like SSL
- Design: Enforce principle of least privilege

## Related pages

- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-287 and CWE-300
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-287 and CWE-693
- [CAPEC-466: Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy](/mitre/capec/CAPEC-466.md), also related to CWE-300
- [CAPEC-589: DNS Blocking](/mitre/capec/CAPEC-589.md), also related to CWE-300
- [CAPEC-590: IP Address Blocking](/mitre/capec/CAPEC-590.md), also related to CWE-300
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-300
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
