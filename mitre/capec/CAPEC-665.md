# CAPEC-665 — Exploitation of Thunderbolt Protection Flaws

<a id="capec-665"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** Low  
**Status:** Stable  

An adversary leverages a firmware weakness within the Thunderbolt protocol, on a computing device to manipulate Thunderbolt controller firmware in order to exploit vulnerabilities in the implementation of authorization and verification schemes within Thunderbolt protection mechanisms. Upon gaining physical access to a target device, the adversary conducts high-level firmware manipulation of the victim Thunderbolt controller SPI (Serial Peripheral Interface) flash, through the use of a SPI Programing device and an external Thunderbolt device, typically as the target device is booting up. If successful, this allows the adversary to modify memory, subvert authentication mechanisms, spoof identities and content, and extract data and memory from the target device. Currently 7 major vulnerabilities exist within Thunderbolt protocol with 9 attack vectors as noted in the Execution Flow.

## Mapped ATT&CK techniques (3)

- [T1211 — Exploitation for Defense Evasion](/mitre/techniques/T1211.md) — Adversaries may exploit a system or application vulnerability to bypass security features.
- [T1542.002 — Component Firmware](/mitre/techniques/T1542-002.md) — Adversaries may modify component firmware to persist on systems.
- [T1556 — Modify Authentication Process](/mitre/techniques/T1556.md) — Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.

## Related CWE (5)

- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.
- [CWE-353 — Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html) — The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.
- [CWE-288 — Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html) — The product requires authentication, but the product has an alternate path or channel that does not require authentication.
- [CWE-1188 — Initialization of a Resource with an Insecure Default](https://cwe.mitre.org/data/definitions/1188.html) — The product initializes or sets a resource with a default that is intended to be changed by the product's installer, administrator, or maintainer, but the default is not secure.
- [CWE-862 — Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) — The product does not perform an authorization check when an actor attempts to access a resource or perform an action.

## Prerequisites

- The adversary needs at least a few minutes of physical access to a system with an open Thunderbolt port, version 3 or lower, and an external thunderbolt device controlled by the adversary with maliciously crafted software and firmware, via an SPI Programming device, to exploit weaknesses in security protections.

## Skills required

- [High] Detailed knowledge on various system motherboards, PCI Express Domain, SPI, and Thunderbolt Protocol in order to interface with internal system components via external devices.
- [High] Detailed knowledge on OS/Kernel memory address space, Direct Memory Access (DMA) mapping, Input-Output Memory Management Units (IOMMUs), and vendor memory protections for data leakage.
- [High] Detailed knowledge on scripting and SPI programming in order to configure and modify Thunderbolt controller firmware and software configurations.

## Consequences

- Access Control / Bypass Protection Mechanism
- Confidentiality / Read Data
- Integrity / Modify Data
- Authorization / Execute Unauthorized Commands

## Mitigations

- Implementation: Kernel Direct Memory Access Protection
- Configuration: Enable UEFI option USB Passthrough mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface
- Configuration: Enable UEFI option DisplayPort mode - Thunderbolt 3 system port operates as video-only DP interface
- Configuration: Enable UEFI option Mixed USB/DisplayPort mode - Thunderbolt 3 system port operates as USB 3.1 Type C interface with support for DP mode
- Configuration: Set Security Level to SL3 for Thunderbolt 2 system port
- Configuration: Disable PCIe tunneling to set Security Level to SL3
- Configuration: Disable Boot Camp upon MacOS systems

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
