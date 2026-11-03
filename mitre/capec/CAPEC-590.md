# CAPEC-590: IP Address Blocking

<a id="capec-590"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Draft  

An adversary performing this type of attack drops packets destined for a target IP address. The aim is to prevent access to the service hosted at the target IP address.

## Related CWE (1)

- [CWE-300: Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html): The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.

## Prerequisites

- This attack requires the ability to conduct deep packet inspection with an In-Path device that can drop the targeted traffic and/or connection.

## Consequences

- Availability / Other

## Mitigations

- Have a large pool of backup IPs built into the application and support proxy capability in the application.

## Related pages

- [CAPEC-57: Utilizing REST's Trust in the System Resource to Obtain Sensitive Data](/mitre/capec/CAPEC-57.md), also related to CWE-300
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-300
- [CAPEC-466: Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy](/mitre/capec/CAPEC-466.md), also related to CWE-300
- [CAPEC-589: DNS Blocking](/mitre/capec/CAPEC-589.md), also related to CWE-300
- [CAPEC-612: WiFi MAC Address Tracking](/mitre/capec/CAPEC-612.md), also related to CWE-300
- [CAPEC-613: WiFi SSID Tracking](/mitre/capec/CAPEC-613.md), also related to CWE-300
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
