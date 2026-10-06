# CAPEC-700: Network Boundary Bridging

<a id="capec-700"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary which has gained elevated access to network boundary devices may use these devices to create a channel to bridge trusted and untrusted networks. Boundary devices do not necessarily have to be on the network’s edge, but rather must serve to segment portions of the target network the adversary wishes to cross into.

## Mapped ATT&CK techniques (1)

- [T1599: Network Boundary Bridging](/mitre/techniques/T1599.md): Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation.

## Prerequisites

- The adversary must have control of a network boundary device.

## Skills required

- [Medium] The adversary must understand how to manage the target network device to create or edit policies which will bridge networks.

## Consequences

- Confidentiality, Access Control / Read Data, Bypass Protection Mechanism
- Integrity, Authorization / Alter Execution Logic, Hide Activities

## Mitigations

- Design: Ensure network devices are storing credentials in encrypted stores
- Design: Follow the principle of least privilege and restrict administrative duties to as few accounts as possible. Ensure these privileged accounts are secured with strong credentials which do not overlap with other network devices.
- Configuration: When possible, configure network boundary devices to use MFA.
- Configuration: Change the default configuration for network devices to harden their security profiles. Default configurations are often enabled with insecure features to allow ease of installation and management. However, these configurations can be easily discovered and exploited by adversaries.
- Implementation: Perform integrity checks on audit logs for network device management and review them to identify abnormalities in configurations.
- Implementation: Prevent network boundary devices from being physically accessed by unauthorized personnel to prevent tampering.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
