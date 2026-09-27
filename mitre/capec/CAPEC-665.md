# CAPEC-665 — Exploitation of Thunderbolt Protection Flaws

<a id="capec-665"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Low

An adversary leverages a firmware weakness within the Thunderbolt protocol, on a computing device to manipulate Thunderbolt controller firmware in order to exploit vulnerabilities in the implementation of authorization and verification schemes within Thunderbolt protection mechanisms. Upon gaining physical access to a target device, the adversary conducts high-level firmware manipulation of the vi

## Mapped ATT&CK techniques (3)

- [T1211](/mitre/techniques/T1211.md)
- [T1542.002](/mitre/techniques/T1542-002.md)
- [T1556](/mitre/techniques/T1556.md)

## Related CWE (5)

[CWE-345](/CWE_REFERENCE.md) [CWE-353](/CWE_REFERENCE.md) [CWE-288](/CWE_REFERENCE.md) [CWE-1188](/CWE_REFERENCE.md) [CWE-862](/CWE_REFERENCE.md)

**Prerequisites:** ::The adversary needs at least a few minutes of physical access to a system with an open Thunderbolt port, version 3 or lower, and an external thunderbolt device controlled by the adversary with malic

**Skills required:** ::SKILL:Detailed knowledge on various system motherboards, PCI Express Domain, SPI, and Thunderbolt Protocol in order to interface with internal syste

**Mitigations:** ::Implementation: Kernel Direct Memory Access Protection::Configuration: Enable UEFI option USB Passthrough mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface::Configuration: Enable UEFI option DisplayPort mode - Thunderbolt 3 syst


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
