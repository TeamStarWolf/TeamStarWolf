# CAPEC-536: Data Injected During Configuration

<a id="capec-536"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Low  
Status: Stable  

An attacker with access to data files and processes on a victim's system injects malicious data into critical operational data during configuration or recalibration, causing the victim's system to perform in a suboptimal manner that benefits the adversary.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Prerequisites

- The attacker must have previously compromised the victim's systems or have physical access to the victim's systems.
- Advanced knowledge of software and hardware capabilities of a manufacturer's product.

## Skills required

- [High] Ability to generate and inject false data into operational data into a system with the intent of causing the victim to alter the configuration of the system.

## Mitigations

- Ensure that proper access control is implemented on all systems to prevent unauthorized access to system files and processes.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
