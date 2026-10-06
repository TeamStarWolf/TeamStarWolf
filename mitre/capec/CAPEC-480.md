# CAPEC-480: Escaping Virtualization

<a id="capec-480"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: Low  
Status: Draft  

An adversary gains access to an application, service, or device with the privileges of an authorized or privileged user by escaping the confines of a virtualized environment. The adversary is then able to access resources or execute unauthorized code within the host environment, generally with the privileges of the user running the virtualized process. Successfully executing an attack of this type is often the first step in executing more complex attacks.

## Mapped ATT&CK techniques (1)

- [T1611: Escape to Host](/mitre/techniques/T1611.md): Adversaries may break out of a container or virtualized environment to gain access to the underlying host.

## Related CWE (1)

- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Consequences

- Access Control, Authorization / Bypass Protection Mechanism
- Authorization / Execute Unauthorized Commands
- Accountability, Authentication, Authorization, Non-Repudiation / Gain Privileges

## Mitigations

- Ensure virtualization software is current and up-to-date.
- Abide by the least privilege principle to avoid assigning users more privileges than necessary.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
