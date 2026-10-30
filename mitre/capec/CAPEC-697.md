# CAPEC-697: DHCP Spoofing

<a id="capec-697"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Low  
Status: Stable  
OpenCRE: [CAPEC-697](https://opencre.org/smartlink/standard/CAPEC/697)  

An adversary masquerades as a legitimate Dynamic Host Configuration Protocol (DHCP) server by spoofing DHCP traffic, with the goal of redirecting network traffic or denying service to DHCP.

## Mapped ATT&CK techniques (1)

- [T1557.003: DHCP Spoofing](/mitre/techniques/T1557-003.md): Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network.

## Related CWE (1)

- [CWE-923: Improper Restriction of Communication Channel to Intended Endpoints](https://cwe.mitre.org/data/definitions/923.html): The product establishes a communication channel to (or from) an endpoint for privileged or protected operations, but it does not properly ensure that it is communicating with the correct endpoint.

## Prerequisites

- The adversary must have access to a machine within the target LAN which can send DHCP offers to the target.

## Skills required

- [Medium] The adversary must identify potential targets for DHCP Spoofing and craft network configurations to obtain the desired results.

## Consequences

- Confidentiality, Access Control / Read Data
- Integrity, Access Control / Modify Data, Execute Unauthorized Commands
- Availability / Resource Consumption

## Mitigations

- Design: MAC-Forced Forwarding
- Implementation: Port Security and DHCP snooping
- Implementation: Network-based Intrusion Detection Systems

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
