# CAPEC-616: Establish Rogue Location

<a id="capec-616"></a>

Abstraction: Standard  
Typical severity: Medium  
Likelihood: Medium  
Status: Stable  

An adversary provides a malicious version of a resource at a location that is similar to the expected location of a legitimate resource. After establishing the rogue location, the adversary waits for a victim to visit the location and access the malicious resource.

## Mapped ATT&CK techniques (1)

- [T1036.005: Match Legitimate Resource Name or Location](/mitre/techniques/T1036-005.md): Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when naming/placing them.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- A resource is expected to available to the user.

## Skills required

- [Low] Adversaries can often purchase low-cost technology to implement rogue access points.

## Consequences

- Confidentiality, Integrity / Other

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
