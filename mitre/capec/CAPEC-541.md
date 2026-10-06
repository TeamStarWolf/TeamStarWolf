# CAPEC-541: Application Fingerprinting

<a id="capec-541"></a>

Abstraction: Standard  
Typical severity: Low  
Status: Draft  

An adversary engages in fingerprinting activities to determine the type or version of an application installed on a remote target.

## Mapped ATT&CK techniques (1)

- [T1592.002: Software](/mitre/techniques/T1592-002.md): Adversaries may gather information about the victim's host software that can be used during targeting.

## Related CWE (3)

- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html): The product provides different responses to incoming requests in a way that reveals internal state information to an unauthorized actor outside of the intended control sphere.
- [CWE-205: Observable Behavioral Discrepancy](https://cwe.mitre.org/data/definitions/205.html): The product's behaviors indicate important differences that may be observed by unauthorized actors in a way that reveals (1) its internal state or decision process, or (2) differences from other products with equivalent functionality.
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html): Two separate operations in a product require different amounts of time to complete, in a way that is observable to an actor and reveals security-relevant information about the state of the product, such as whether a particular operation was successful or not.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
